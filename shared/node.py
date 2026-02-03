"""Universal node deployment class"""
import logging
import tempfile
import tarfile
import time
import shlex
from pathlib import Path
from typing import Dict, Optional, Literal, Tuple
from shared.providers import get_provider, SCRUBBER_SUPPORTED_PROVIDERS
from shared.models import InstanceCreateResult
from shared.config import get_settings
from shared.utils.ssh import create_ssh_client
from shared.utils.logging import get_logger

logger = get_logger(__name__)


class Node:
    """
    Universal node deployment class with convention-based config loading.

    Features:
    - Loads bootstrap scripts: configs/{node_type}-{provider}-*.sh
    - Uses tp.env defaults if region/instance_type not specified
    - Template variable substitution (${VAR_NAME})
    - Pure REST API calls to cloud providers

    Example:
        # Use defaults from tp.env
        node = Node(node_type="scrubber")

        # Override defaults
        node = Node(
            node_type="scrubber",
            region="us-west-2",
            instance_type="c5n.large"
        )

        result = node.deploy()
    """

    def __init__(
        self,
        node_type: Literal["scrubber", "exit_hub", "origin", "attacker", "webclient"],
        region: Optional[str] = None,
        instance_type: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        **template_vars
    ):
        self.settings = get_settings()
        self.node_type = node_type

        # Apply defaults from tp.env if not specified
        self.region = region or self._get_default_region()
        self.instance_type = instance_type or self._get_default_instance_type()
        self.cloud_provider = cloud_provider or self._get_default_provider()

        # Enforce provider restrictions per node type
        if self.node_type == "scrubber" and self.cloud_provider not in SCRUBBER_SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unsupported provider '{self.cloud_provider}' for scrubbers. "
                f"Only AWS is currently supported for scrubber deployment and management. "
                f"Supported: {list(SCRUBBER_SUPPORTED_PROVIDERS)}"
            )

        self.template_vars = template_vars
        self.provider = get_provider(self.cloud_provider)

    def deploy(
        self,
        tags: Optional[Dict[str, str]] = None,
        skip_asset_embedding: bool = False
    ) -> InstanceCreateResult:
        """
        Deploy node:
        1. Build cloud-init from config scripts
        2. Call provider.create_instance() (pure REST API)
        3. Return deployment result

        Args:
            tags: Tags to apply to instance
            skip_asset_embedding: If True, don't embed assets in user_data.
                                 Use this when post_provision() will be called.
                                 Keeps user_data small for cloud provider limits.

        Returns:
            InstanceCreateResult with instance details
        """
        from datetime import datetime

        user_data = self._build_cloud_init(skip_assets=skip_asset_embedding)

        if tags is None:
            tags = {}
        tags['node_type'] = self.node_type

        # Add timestamp to Name tag for unique identification
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        if 'Name' not in tags:
            tags['Name'] = f"{self.node_type}-{timestamp}"

        result = self.provider.create_instance(
            region=self.region,
            instance_type=self.instance_type,
            user_data=user_data,
            tags=tags
        )

        return InstanceCreateResult(**result)

    def destroy(self, instance_id: str) -> bool:
        """Destroy instance via provider REST API"""
        return self.provider.delete_instance(instance_id, region=self.region)

    def get_status(self, instance_id: str) -> str:
        """Get instance status via provider REST API"""
        return self.provider.get_instance_status(instance_id)

    # ========================================================================
    # Post-Provisioning (for large assets exceeding user_data limits)
    # ========================================================================

    def create_asset_bundle(self, output_path: Optional[str] = None) -> Optional[str]:
        """
        Create tarball from configs/assets/{node_type}/.
        Can be called from ANY service (Miner, Traffic Manager, TensorProx).

        Args:
            output_path: Where to save tarball. If None, creates in /tmp/

        Returns:
            Path to created tarball, or None if no assets exist
        """
        # Use absolute path from project root (parent of shared/)
        project_root = Path(__file__).resolve().parent.parent
        assets_dir = project_root / "configs" / "assets" / self.node_type

        if not assets_dir.exists() or not assets_dir.is_dir():
            return None

        if output_path is None:
            tmp_file = tempfile.NamedTemporaryFile(
                delete=False,
                suffix=f"-{self.node_type}-bundle.tar.gz"
            )
            output_path = tmp_file.name
            tmp_file.close()

        with tarfile.open(output_path, "w:gz") as tar:
            tar.add(assets_dir, arcname=".")

        return output_path

    def post_provision(
        self,
        instance_ip: str,
        bundle_path: str,
        ssh_key_path: Optional[str] = None,
        ssh_username: Optional[str] = None,
        extract_to: Optional[str] = None,
        command_timeout: int = 120,
    ) -> Tuple[bool, Optional[str]]:
        """
        Upload asset bundle and extract via SSH.
        Service-agnostic - works for Miner, Traffic Manager, TensorProx.

        Extraction Strategy (provider-aware):
        - ALWAYS extract to provider.default_home_dir (base directory)
        - Scrubber bundle contains assets/ → extracts to /home/ubuntu/assets/
        - Origin flat bundle → extracts then organized into /home/ubuntu/assets/origin/

        Args:
            instance_ip: IP address of deployed instance
            bundle_path: Path to tarball (from create_asset_bundle())
            ssh_key_path: SSH private key path (defaults to tp.env)
            ssh_username: SSH username (defaults to provider.default_ssh_user)
            extract_to: Base extraction directory (defaults to provider.default_home_dir)

        Returns:
            Tuple of (success, error_message). error_message is None on success.
        """

        logger = get_logger(__name__)

        import os
        # Use provider-specific defaults
        if ssh_key_path is None:
            ssh_key_path = self.settings.ssh_key_path
        # Expand ~ to home directory
        ssh_key_path = os.path.expanduser(ssh_key_path)

        if ssh_username is None:
            ssh_username = self.provider.default_ssh_user

        if extract_to is None:
            extract_to = self.provider.default_home_dir

        logger.debug(f"Post-provision [{self.node_type}]: user={ssh_username}, extract_to={extract_to}")

        try:
            from shared.utils.ssh import sftp_upload, create_ssh_client

            # Upload bundle via centralized SFTP helper
            remote_path = '/tmp/asset-bundle.tar.gz'
            logger.debug(f"Uploading bundle to {instance_ip}:{remote_path}")
            upload_success, upload_error = sftp_upload(
                host=instance_ip,
                username=ssh_username,
                key_filename=ssh_key_path,
                local_path=bundle_path,
                remote_path=remote_path,
                timeout=30
            )

            if not upload_success:
                logger.error("Bundle upload failed")
                return False, upload_error

            # Create SSH client for extraction commands
            ssh = create_ssh_client(instance_ip, ssh_username, ssh_key_path, timeout=30)

            staging_dir = f"{extract_to}/.rf-{self.node_type}-bundle"
            prep_cmd = f'rm -rf {staging_dir} && mkdir -p {staging_dir}'
            logger.debug(f"Preparing staging directory: {staging_dir}")
            stdin, stdout, stderr = ssh.exec_command(prep_cmd, timeout=command_timeout)
            prep_exit = stdout.channel.recv_exit_status()

            if prep_exit != 0:
                error = stderr.read().decode()
                error_msg = f"Staging directory prep failed (exit {prep_exit}): {error}"
                logger.error(error_msg)
                ssh.close()
                return False, error_msg

            # Extract to staging directory to avoid touching {extract_to} metadata
            extract_cmd = f'tar -xzf {remote_path} -C {staging_dir}/'
            logger.debug(f"Extracting: {extract_cmd}")
            stdin, stdout, stderr = ssh.exec_command(extract_cmd, timeout=command_timeout)
            exit_code = stdout.channel.recv_exit_status()

            if exit_code != 0:
                error = stderr.read().decode()
                error_msg = f"Extraction failed (exit {exit_code}): {error}"
                logger.error(error_msg)
                ssh.close()
                return False, error_msg

            # Copy staged files into the provider home directory
            copy_cmd = f'cp -r {staging_dir}/. {extract_to}/'
            logger.debug(f"Copying staged assets into {extract_to}")
            stdin, stdout, stderr = ssh.exec_command(copy_cmd, timeout=command_timeout)
            copy_exit = stdout.channel.recv_exit_status()

            if copy_exit != 0:
                error = stderr.read().decode()
                error_msg = f"Copy from staging failed (exit {copy_exit}): {error}"
                logger.error(error_msg)
                ssh.close()
                return False, error_msg

            ssh.exec_command(f'rm -rf {staging_dir}')

            # Node-type specific organization (minimal code)
            if self.node_type in ['origin', 'webclient', 'attacker']:
                # Flat bundles need assets/{node_type}/ wrapper for script references
                organize_cmd = f'mkdir -p {extract_to}/assets/{self.node_type} && mv {extract_to}/*.py {extract_to}/*.sh {extract_to}/assets/{self.node_type}/ 2>/dev/null || true'
                logger.debug(f"Organizing {self.node_type} assets")
                ssh.exec_command(organize_cmd)

            # Verify extraction
            verify_cmd = f'ls -la {extract_to}/ | head -10; echo "=== assets/ ==="; ls -la {extract_to}/assets/ 2>/dev/null | head -10 || echo "No assets dir"'
            stdin, stdout, stderr = ssh.exec_command(verify_cmd, timeout=command_timeout)
            listing = stdout.read().decode()
            logger.debug(f"Post-extraction verification:\n{listing}")

            # Make all scripts executable
            chmod_cmd = f'find {extract_to} -type f \\( -name "*.sh" -o -name "*.py" \\) -exec chmod +x {{}} \\;'
            ssh.exec_command(chmod_cmd, timeout=command_timeout)

            ssh.close()
            logger.info(f"Post-provision complete [{self.node_type}]: {extract_to}")
            return True, None

        except Exception as e:
            error_msg = f"Post-provision failed: {e}"
            logger.error(error_msg)
            return False, error_msg

    def _get_bootstrap_script_path(self) -> Optional[str]:
        """
        Determine bootstrap script path based on provider home and node type.

        Provider-aware modular path construction:
        - Base: provider.default_home_dir (/root for Linode, /home/ubuntu for AWS)
        - Scrubber/exit_hub: {base}/bootstrap_inner.sh
        - Origin: {base}/assets/origin/setup-servers.sh
        - Webclient/attacker: None (no bootstrap scripts)

        Returns:
            Absolute path to bootstrap script, or None if no bootstrap for this node type
        """
        base = self.provider.default_home_dir

        # Node-type specific bootstrap scripts
        bootstrap_scripts = {
            'scrubber': f'{base}/bootstrap_inner.sh',
            'exit_hub': f'{base}/bootstrap_inner.sh',
            'origin': f'{base}/assets/origin/setup-servers.sh'
        }

        return bootstrap_scripts.get(self.node_type)

    def execute_bootstrap(
        self,
        instance_ip: str,
        bootstrap_script: Optional[str] = None,
        ssh_key_path: Optional[str] = None,
        ssh_username: Optional[str] = None,
        timeout: int = 600,
        max_retries: int = 2,
        env_vars: Optional[dict] = None
    ) -> tuple[bool, str]:
        """
        Execute bootstrap script on remote instance via SSH with retry logic.

        Universal method - works for scrubbers, origins, exit hubs, etc.
        Bootstrap script path auto-constructed from provider + node_type.

        Args:
            instance_ip: IP address of instance
            bootstrap_script: Path to bootstrap script on remote instance
                            (defaults from _get_bootstrap_script_path())
            ssh_key_path: SSH private key path (defaults to tp.env)
            ssh_username: SSH username (defaults to provider.default_ssh_user)
            timeout: Command timeout in seconds (default: 600 = 10 minutes)
            max_retries: Number of retry attempts (default: 2 for APT lock tolerance)
            env_vars: Optional environment variables to pass to bootstrap script

        Returns:
            Tuple of (success: bool, output: str)
        """
                
        logger = get_logger(__name__)

        import os
        # Use provider-specific defaults
        if ssh_key_path is None:
            ssh_key_path = self.settings.ssh_key_path
        # Expand ~ to home directory
        ssh_key_path = os.path.expanduser(ssh_key_path)

        if ssh_username is None:
            ssh_username = self.provider.default_ssh_user

        # Dynamically construct bootstrap script path if not provided
        if bootstrap_script is None:
            bootstrap_script = self._get_bootstrap_script_path()

        # If no bootstrap script for this node type, return success
        if bootstrap_script is None:
            logger.debug(f"No bootstrap script for node_type={self.node_type}, skipping")
            return True, "No bootstrap required for this node type"

        logger.debug(f"execute_bootstrap [{self.node_type}]: script={bootstrap_script}, user={ssh_username}")

        for attempt in range(1, max_retries + 1):
            ssh = None
            try:
                # Use centralized SSH client creation
                ssh = create_ssh_client(instance_ip, ssh_username, ssh_key_path, timeout=30)

                logger.info(f"Bootstrap attempt {attempt}/{max_retries}: {bootstrap_script}")

                # Build command with environment variables
                # Use bash -c with export to ensure env vars are available inside script
                if env_vars:
                    assignments = " ".join(
                        f"{key}={shlex.quote(str(value))}"
                        for key, value in env_vars.items()
                    )
                    command = f"sudo env {assignments} bash {shlex.quote(bootstrap_script)}"
                    logger.debug(f"Command: {command}")
                else:
                    command = f"sudo bash {shlex.quote(bootstrap_script)}"
                stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)

                # Wait for command to complete
                exit_code = stdout.channel.recv_exit_status()

                # Capture output
                stdout_text = stdout.read().decode('utf-8', errors='replace')
                stderr_text = stderr.read().decode('utf-8', errors='replace')
                combined_output = stdout_text + stderr_text

                if exit_code == 0:
                    logger.info(f"Bootstrap succeeded on attempt {attempt}")
                    return True, combined_output
                else:
                    logger.warning(f"Bootstrap attempt {attempt} failed (exit {exit_code})")
                    if attempt < max_retries:
                        logger.info(f"Retrying in 30 seconds...")
                        time.sleep(30)
                    else:
                        logger.error(f"Bootstrap failed after {max_retries} attempts")
                        return False, combined_output

            except Exception as e:
                logger.error(f"Bootstrap attempt {attempt} exception: {e}")
                if attempt < max_retries:
                    logger.info(f"Retrying in 30 seconds...")
                    time.sleep(30)
                else:
                    return False, f"SSH execution failed after {max_retries} attempts: {str(e)}"
            finally:
                if ssh is not None:
                    ssh.close()

        return False, f"Bootstrap failed after {max_retries} attempts"

    def cleanup_remote_files(
        self,
        instance_ip: str,
        paths: list[str],
        ssh_key_path: Optional[str] = None,
        ssh_username: Optional[str] = None
    ) -> bool:
        """
        Remove temporary files from remote instance via SSH.

        Universal method - works for any node type.

        Args:
            instance_ip: IP address of instance
            paths: List of file/directory paths to remove
            ssh_key_path: SSH private key path (defaults to tp.env)
            ssh_username: SSH username (defaults to provider.default_ssh_user)

        Returns:
            True if successful, False otherwise
        """
        
        if ssh_key_path is None:
            ssh_key_path = self.settings.ssh_key_path

        if ssh_username is None:
            ssh_username = self.provider.default_ssh_user

        try:
            # Use centralized SSH client creation
            ssh = create_ssh_client(instance_ip, ssh_username, ssh_key_path, timeout=30)

            all_successful = True
            for path in paths:
                command = f"sudo rm -rf {path}"
                stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
                exit_code = stdout.channel.recv_exit_status()

                if exit_code == 0:
                    logger.debug(f"Removed: {path}")
                else:
                    stderr_text = stderr.read().decode()
                    logger.warning(f"Failed to remove {path}: {stderr_text}")
                    all_successful = False

            ssh.close()
            return all_successful

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return False

    def get_primary_eni_id(self, instance_id: str) -> Optional[str]:
        """
        Retrieve primary ENI ID (device index 0) for an instance.

        Only works for AWS provider.

        Args:
            instance_id: Instance ID to query

        Returns:
            ENI ID or None if not found or provider doesn't support ENIs
        """
        if self.cloud_provider != "aws":
            return None

        # Call AWS provider's describe_network_interfaces with region
        enis = self.provider.describe_network_interfaces(instance_id, region=self.region)

        # Find primary ENI (device index 0)
        for eni in enis:
            if eni['device_index'] == 0:
                return eni['network_interface_id']

        return None

    def wait_for_ssh(
        self,
        host: str,
        max_attempts: int = 30,
        interval: int = 5,
        timeout: int = 5,
        deadline_seconds: Optional[int] = None,
    ) -> bool:
        """
        Wait for SSH to become available on a host.

        Uses provider-specific default user (AWS: ubuntu, Linode: root).

        Args:
            host: IP address or hostname to connect to
            max_attempts: Maximum number of connection attempts (default: 30)
            interval: Seconds to wait between attempts (default: 5)
            timeout: SSH connection timeout in seconds (default: 5)

        Returns:
            True if SSH is ready, False if timeout reached

        Raises:
            Exception: If SSH is not ready after max_attempts
        """
               

        logger = logging.getLogger(__name__)
        ssh_username = getattr(self.provider, 'default_ssh_user', 'ubuntu')

        logger.info(f"Waiting for SSH on {host} (user: {ssh_username}, max_attempts: {max_attempts})")
        start_time = time.time()
        warn_threshold = max(3, max_attempts // 3)

        def _log_attempt_failure(attempt_number: int, error: Exception):
            elapsed = time.time() - start_time
            message = (
                f"SSH attempt {attempt_number}/{max_attempts} failed on {host} "
                f"after {elapsed:.1f}s: {error}"
            )
            if attempt_number >= warn_threshold:
                logger.warning(message)
            else:
                logger.debug(message)

        import os
        ssh_key_path = os.path.expanduser(self.settings.ssh_key_path)
        for attempt in range(1, max_attempts + 1):
            try:
                # Use centralized SSH client creation
                ssh = create_ssh_client(host, ssh_username, ssh_key_path, timeout=timeout)
                ssh.close()
                total = time.time() - start_time
                logger.info(f"SSH ready on {host} after {attempt} attempts ({total:.1f}s elapsed)")
                return True
            except Exception as e:
                if deadline_seconds and (time.time() - start_time) >= deadline_seconds:
                    logger.error(
                        f"SSH deadline reached on {host} after {time.time() - start_time:.1f}s"
                    )
                    raise TimeoutError(f"SSH not reachable on {host} within {deadline_seconds}s") from e
                if attempt < max_attempts:
                    _log_attempt_failure(attempt, e)
                    time.sleep(interval)
                    continue
                else:
                    _log_attempt_failure(attempt, e)
                    logger.error(f"SSH not ready on {host} after {max_attempts} attempts: {e}")
                    raise TimeoutError(f"SSH connection timeout for {host}") from e

        return False

    # ========================================================================
    # Default Resolution (from tp.env)
    # ========================================================================

    def _get_default_region(self) -> str:
        """Get default region for node type from tp.env"""
        defaults = {
            "scrubber": self.settings.scrubber_region,
            "exit_hub": self.settings.exit_hub_region,
            "origin": self.settings.origin_region,
            "attacker": self.settings.attacker_region,
            "webclient": self.settings.webclient_region,
        }
        return defaults[self.node_type]

    def _get_default_instance_type(self) -> str:
        """Get default instance type for node type from tp.env"""
        defaults = {
            "scrubber": self.settings.scrubber_instance_type,
            "exit_hub": self.settings.exit_hub_instance_type,
            "origin": self.settings.origin_instance_type,
            "attacker": self.settings.attacker_instance_type,
            "webclient": self.settings.webclient_instance_type,
        }
        return defaults[self.node_type]

    def _get_default_provider(self) -> str:
        """Get default cloud provider for node type from settings"""
        defaults = {
            "scrubber": self.settings.scrubber_provider,
            "exit_hub": self.settings.exit_hub_provider,
            "origin": self.settings.origin_provider,
            "attacker": self.settings.attacker_provider,
            "webclient": self.settings.webclient_provider,
        }
        return defaults[self.node_type]

    # ========================================================================
    # Cloud-Init Builder
    # ========================================================================

    def _build_cloud_init(self, skip_assets: bool = False) -> str:
        """
        Load config scripts matching: configs/{node_type}-{provider}-*.sh
        Sort alphabetically, combine, substitute template variables.
        Auto-embed assets from configs/assets/{node_type}/ if directory exists.

        Args:
            skip_assets: If True, don't embed assets (for post-provisioning instead)

        Returns:
            Complete cloud-init/user_data script
        """
        # Use absolute path from project root (parent of shared/)
        project_root = Path(__file__).resolve().parent.parent
        config_dir = project_root / "configs"
        pattern = f"{self.node_type}-{self.cloud_provider}-*.sh"

        scripts = sorted(config_dir.glob(pattern))

        if not scripts:
            raise ValueError(
                f"No config scripts found for {self.node_type} on {self.cloud_provider}. "
                f"Expected pattern: configs/{pattern}"
            )

        # Build combined script
        combined = "#!/bin/bash\n"
        combined += "set -euo pipefail\n\n"
        combined += f"# Node Type: {self.node_type}\n"
        combined += f"# Provider: {self.cloud_provider}\n"
        combined += f"# Region: {self.region}\n"
        combined += f"# Instance Type: {self.instance_type}\n"
        combined += f"# Generated by TensorProx Node class\n\n"

        # Part 1: Bootstrap scripts
        for script_path in scripts:
            with open(script_path, 'r') as f:
                content = f.read()

                # Template variable substitution
                for key, value in self.template_vars.items():
                    content = content.replace(f"${{{key}}}", str(value))

                combined += f"\n# === {script_path.name} ===\n"
                combined += content
                combined += "\n\n"

        # Part 2: Auto-embed assets if not skipped
        if not skip_assets:
            assets_dir = project_root / "configs" / "assets" / self.node_type
            if assets_dir.exists() and assets_dir.is_dir():
                combined += self._embed_assets(assets_dir)

        return combined

    def _embed_assets(self, assets_dir: Path) -> str:
        """
        Generic method to embed files as base64 in cloud-init.
        Works for ANY node type (attacker, webclient, scrubber, etc.).

        Files are extracted to /root/{relative_path} on instance boot.

        Args:
            assets_dir: Path to configs/assets/{node_type}/

        Returns:
            Bash script block that decodes and extracts assets
        """
        import base64

        asset_block = "\n# === Auto-embedded assets ===\n"
        asset_block += f"# Files from {assets_dir}\n\n"

        # Find all files recursively
        asset_files = sorted([f for f in assets_dir.rglob("*") if f.is_file()])

        if not asset_files:
            return ""

        asset_block += "echo 'Extracting embedded assets...'\n\n"

        for asset_file in asset_files:
            # Read and base64 encode
            with open(asset_file, 'rb') as f:
                content_b64 = base64.b64encode(f.read()).decode()

            # Determine destination path (preserve directory structure)
            relative_path = asset_file.relative_to(assets_dir)
            dest_path = f"/root/{relative_path}"
            dest_dir = str(Path(dest_path).parent)

            # Create directory if needed
            if dest_dir != "/root":
                asset_block += f"mkdir -p {dest_dir}\n"

            # Write file using base64 heredoc
            asset_block += f"\n# Extract: {relative_path}\n"
            asset_block += f"base64 -d > {dest_path} << 'ASSET_EOF'\n"
            asset_block += f"{content_b64}\n"
            asset_block += f"ASSET_EOF\n"
            asset_block += f"chmod +x {dest_path}\n"

        asset_block += "\necho 'Assets extracted successfully'\n"

        return asset_block
