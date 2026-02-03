"""TPM API blueprints for exit hub lifecycle management."""

from tensorprox.tpm.api.exit_hubs import bp as exit_hubs_bp
from tensorprox.tpm.api.origins import bp as origins_bp
from tensorprox.tpm.api.miners import bp as miners_bp
from tensorprox.tpm.api.streams import bp as streams_bp
from tensorprox.tpm.api.subnet import bp as subnet_bp
from tensorprox.tpm.api.validators import bp as validators_bp
from tensorprox.tpm.api.tpm_keys import bp as tpm_keys_bp
from tensorprox.tpm.api.miner_events import bp as miner_events_bp
from tensorprox.tpm.api.miner_ports import bp as miner_ports_bp
from tensorprox.tpm.api.admin_cleanup import bp as admin_cleanup_bp
from tensorprox.tpm.api.benign_tests import bp as benign_tests_bp

__all__ = [
    "exit_hubs_bp",
    "origins_bp",
    "miners_bp",
    "streams_bp",
    "subnet_bp",
    "validators_bp",
    "tpm_keys_bp",
    "miner_events_bp",
    "miner_ports_bp",
    "admin_cleanup_bp",
    "benign_tests_bp",
]
