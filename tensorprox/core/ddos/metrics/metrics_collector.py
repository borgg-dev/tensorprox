#!/usr/bin/env python3
"""
Metrics Collector for TensorProx DDoS Protection

This module collects performance and operational metrics from the DDoS protection system.
"""

import time
import threading
import queue
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from collections import defaultdict, deque
from loguru import logger

from tensorprox.core.ddos.config.config_manager import ConfigManager

class MetricsCollector:
    """
    Collects and maintains metrics from the DDoS protection system.
    """
    
    def __init__(self, config_manager: ConfigManager, bpf_loader=None):
        """
        Initialize the metrics collector.
        
        Args:
            config_manager: Configuration manager instance
            bpf_loader: BPF loader instance for XDP interaction (optional)
        """
        self.config_manager = config_manager
        self.bpf_loader = bpf_loader
        
        # Initialize state
        self.running = False
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        
        # Metrics storage
        self.current_metrics = {}
        self.historical_metrics = defaultdict(lambda: deque(maxlen=1000))  # Store up to 1000 data points per metric
        self.events = deque(maxlen=1000)  # Store up to 1000 events
        
        # Configuration
        self.collection_interval = self.config_manager.get_config("metrics", "collection_interval", default=5)
    
    def start(self):
        """
        Start the metrics collector.
        
        Returns:
            True if started successfully, False otherwise
        """
        with self._lock:
            if self.running:
                logger.warning("Metrics Collector is already running")
                return True
            
            self._stop_event.clear()
            self.running = True
            
            try:
                # Start collection thread
                self.collection_thread = threading.Thread(
                    target=self._collection_thread,
                    name="MetricsCollector-Thread"
                )
                self.collection_thread.daemon = True
                self.collection_thread.start()
                
                logger.info(f"Metrics Collector started (collection interval: {self.collection_interval}s)")
                return True
            
            except Exception as e:
                logger.exception(f"Failed to start Metrics Collector: {e}")
                self.running = False
                return False
    
    def _collection_thread(self):
        """Thread function for collecting metrics."""
        logger.debug("Metrics collection thread started")
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Collect metrics
                    metrics = self._collect_metrics()
                    
                    # Update current metrics
                    with self._lock:
                        self.current_metrics = metrics
                        
                        # Add to historical metrics
                        timestamp = datetime.now().isoformat()
                        for key, value in metrics.items():
                            self.historical_metrics[key].append((timestamp, value))
                    
                    # Calculate and log rates
                    self._calculate_rates(metrics)
                
                except Exception as e:
                    logger.error(f"Error collecting metrics: {e}")
                
                # Sleep until next collection
                time.sleep(self.collection_interval)
        
        except Exception as e:
            if not self._stop_event.is_set():
                logger.exception(f"Error in metrics collection thread: {e}")
        
        finally:
            logger.debug("Metrics collection thread exiting")
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """
        Collect metrics from the DDoS protection system.
        
        Returns:
            Dictionary of metrics
        """
        metrics = {}
        
        # Get metrics from BPF loader
        if self.bpf_loader:
            xdp_metrics = self.bpf_loader.get_metrics()
            if xdp_metrics:
                metrics.update(xdp_metrics)
        
        # Add timestamp
        metrics["timestamp"] = time.time()
        
        return metrics
    
    def _calculate_rates(self, metrics: Dict[str, Any]):
        """
        Calculate and log rate metrics.
        
        Args:
            metrics: Current metrics
        """
        # Get previous metrics
        with self._lock:
            if "prev_metrics" not in self.__dict__:
                self.prev_metrics = metrics
                self.prev_time = metrics.get("timestamp", time.time())
                return
            
            # Calculate time delta
            current_time = metrics.get("timestamp", time.time())
            time_delta = current_time - self.prev_time
            
            if time_delta <= 0:
                return
            
            # Calculate packet rates
            try:
                total_packets = metrics.get("total_packets", 0)
                prev_total_packets = self.prev_metrics.get("total_packets", 0)
                packet_rate = (total_packets - prev_total_packets) / time_delta
                
                blocked_packets = metrics.get("blocked_packets", 0)
                prev_blocked_packets = self.prev_metrics.get("blocked_packets", 0)
                block_rate = (blocked_packets - prev_blocked_packets) / time_delta
                
                # Log rates if significant
                if packet_rate > 1000 or block_rate > 100:
                    logger.info(f"Traffic rates: {packet_rate:.2f} pps total, {block_rate:.2f} pps blocked")
                    
                    # Calculate block percentage
                    if packet_rate > 0:
                        block_percentage = (block_rate / packet_rate) * 100
                        logger.info(f"Block percentage: {block_percentage:.2f}%")
            
            except Exception as e:
                logger.error(f"Error calculating rates: {e}")
            
            # Update previous metrics
            self.prev_metrics = metrics
            self.prev_time = current_time
    
    def get_current_metrics(self) -> Dict[str, Any]:
        """
        Get the current metrics.
        
        Returns:
            Dictionary of current metrics
        """
        with self._lock:
            return dict(self.current_metrics)
    
    def get_historical_metrics(self, metric_name: str = None, limit: int = 100) -> Dict[str, List[Tuple[str, Any]]]:
        """
        Get historical metrics.
        
        Args:
            metric_name: Optional name of the metric to get (if None, gets all metrics)
            limit: Maximum number of data points to return for each metric
            
        Returns:
            Dictionary of metric name -> list of (timestamp, value) tuples
        """
        with self._lock:
            if metric_name:
                # Get a specific metric
                history = list(self.historical_metrics.get(metric_name, []))
                return {metric_name: history[-limit:] if limit else history}
            else:
                # Get all metrics
                result = {}
                for name, history in self.historical_metrics.items():
                    result[name] = list(history)[-limit:] if limit else list(history)
                return result
    
    def record_event(self, event_type: str, details: Dict[str, Any]):
        """
        Record an event.
        
        Args:
            event_type: Type of event
            details: Event details
        """
        with self._lock:
            event = {
                "timestamp": datetime.now().isoformat(),
                "type": event_type,
                **details
            }
            self.events.append(event)
    
    def get_events(self, event_type: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recorded events.
        
        Args:
            event_type: Optional type of events to get (if None, gets all events)
            limit: Maximum number of events to return
            
        Returns:
            List of event dictionaries
        """
        with self._lock:
            if event_type:
                # Get specific event type
                events = [e for e in self.events if e["type"] == event_type]
            else:
                # Get all events
                events = list(self.events)
            
            return events[-limit:] if limit else events
    
    def stop(self):
        """
        Stop the metrics collector.
        
        Returns:
            True if stopped successfully, False otherwise
        """
        with self._lock:
            if not self.running:
                logger.warning("Metrics Collector is not running")
                return True
            
            logger.info("Stopping Metrics Collector...")
            
            # Signal collection thread to stop
            self._stop_event.set()
            
            # Wait for collection thread to exit
            if hasattr(self, "collection_thread") and self.collection_thread.is_alive():
                self.collection_thread.join(timeout=2.0)
            
            self.running = False
            logger.info("Metrics Collector stopped")
            return True