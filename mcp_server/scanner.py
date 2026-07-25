import sys
import os
import subprocess
import asyncio
import time
import json
import hashlib
from typing import Dict, Any, List

class BbotScanner:
    """
    BBOT Scanner Class

    Handles execution of BBOT scans via subprocess, tracking their state,
    parsing results, and providing status updates.

    Usage:
        scanner = BbotScanner()
        scan_id = await scanner.execute_scan(scan_config)
        status = await scanner.get_status(scan_id)
        findings = await scanner.get_findings(scan_id, limit=10)
    """

    def __init__(self,
                 bbot_path: str = 'bbot',
                 timeout: int = 300,
                 retries: int = 3,
                 poll_interval: float = 5.0):
        """
        Initialize the BBOT scanner.

        Args:
            bbot_path: Path to the BBOT CLI binary (default: 'bbot', resolved from PATH)
            timeout: Default timeout for scans (seconds)
            retries: Number of automatic retries for failed scans
            poll_interval: Interval for checking running processes
        """
        self.bbot_path = bbot_path
        self.timeout = timeout
        self.retries = retries
        self.poll_interval = poll_interval
        self.active_scans: Dict[str, Dict[str, Any]] = {}
        self.completed_scans: set = set()

        # Create output directory for scan outputs
        self.output_dir = os.path.join(os.path.dirname(__file__), '..', 'scan_outputs')
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_scan_id(self, config: Dict) -> str:
        """
        Generate a unique scan ID based on configuration.

        Args:
            config: Configuration dictionary

        Returns:
            Unique scan ID string
        """
        # Create a hash-like ID from configuration elements
        elements = [
            '_'.join(config.get('targets', [])),
            '_'.join(config.get('presets', [])),
            '_'.join(config.get('modules', [])),
            str(config.get('scan_name', ''))
        ]
        combined = '-'.join(elements)
        if not any(elements):
            scan_id = f"scan_{int(time.time()*1000)}"
        else:
            scan_id = f"scan_{hashlib.sha256(combined.encode()).hexdigest()[:12]}"
        return scan_id

    async def execute_scan(self, scan_config: Dict) -> Dict[str, Any]:
        """
        Execute a BBOT scan with the provided configuration.

        Args:
            scan_config: Dictionary containing scan parameters

        Returns:
            Dictionary with scan ID and status for the started scan

        Raises:
            ValueError: If required configuration is missing
            RuntimeError: If subprocess fails to start
        """
        try:
            if not scan_config or 'targets' not in scan_config or not scan_config['targets']:
                raise ValueError("Scan configuration must include at least one target")

            scan_id = self.generate_scan_id(scan_config)

            # Prepare command line arguments
            cmd_args = [sys.executable, self.bbot_path]

            # Add targets
            for target in scan_config.get('targets', []):
                cmd_args.append('-t')
                cmd_args.append(target)

            # Add presets
            for preset in scan_config.get('presets', []):
                cmd_args.append('-p')
                cmd_args.append(preset)

            # Add modules
            for module in scan_config.get('modules', []):
                cmd_args.append('-m')
                cmd_args.append(module)

            # Add custom scan name if provided
            if scan_config.get('scan_name'):
                cmd_args.append('-n')
                cmd_args.append(scan_config['scan_name'])

            # Execute the process
            process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                close_fds=False
            )

            # Store scan state
            self.active_scans[scan_id] = {
                'id': scan_id,
                'process': process,
                'stderr_buffer': '',
                'stdout_buffer': '',
                'start_time': time.time(),
                'cmd': ' '.join(cmd_args),
                'status': 'in_progress',
                'config': scan_config,
                'output_path': os.path.join(self.output_dir, f"{scan_id}.json"),
                'retries_left': self.retries
            }

            # Start async monitoring of process output
            asyncio.create_task(self._monitor_process(scan_id))

            return {
                'scan_id': scan_id,
                'status': 'in_progress',
                'message': 'Scan started successfully'
            }

        except Exception as e:
            raise RuntimeError(f"Failed to execute scan: {str(e)}") from e

    async def _monitor_process(self, scan_id: str):
        """
        Asynchronously monitor the output of a running scan process.

        This method reads stdout/stderr from the subprocess in real-time,
        updates scan status, and stores output for later retrieval.
        """
        try:
            scan_info = self.active_scans[scan_id]
            process = scan_info['process']

            # Read stdout and stderr concurrently to avoid pipe buffer deadlock
            async def read_stream(stream):
                lines = []
                async for line in self._stream_process_output(stream):
                    lines.append(line)
                return lines

            stdout_lines, stderr_lines = await asyncio.gather(
                read_stream(process.stdout),
                read_stream(process.stderr)
            )

            scan_info['stdout_buffer'] = '\n'.join(stdout_lines)
            scan_info['stderr_buffer'] = '\n'.join(stderr_lines)

            # Process completed - update status
            scan_info['status'] = 'finished'
            now = time.time()
            scan_info['end_time'] = now
            elapsed = now - scan_info.get('start_time', now)
            scan_info['duration'] = round(elapsed, 2)

            # Save full output to file
            await self._save_output_to_file(scan_id)

            # Mark scan as completed
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            self.completed_scans.add(scan_id)

        except Exception as e:
            # Handle process termination errors
            if scan_id in self.active_scans:
                scan_info = self.active_scans[scan_id]
                scan_info['status'] = 'error'
                scan_info['error'] = str(e)
                await self._save_output_to_file(scan_id)

        finally:
            if scan_id in self.active_scans:
                try:
                    scan_info = self.active_scans.get(scan_id)
                    if scan_info:
                        process = scan_info.get('process')
                        if process and process.poll() is None:  # Still running
                            process.terminate()
                        await asyncio.sleep(0.1)  # Give it time to terminate
                except Exception:
                    pass

    async def _stream_process_output(self, stream):
        """
        Stream output from a subprocess stream.

        Args:
            stream: Subprocess stdout or stderr stream

        Yields:
            Lines of output as they become available
        """
        try:
            while True:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, stream.readline
                )
                if not line:  # EOF
                    break
                yield line.rstrip('\n\r')
        except Exception:
            return

    async def _save_output_to_file(self, scan_id: str):
        """
        Save the complete output of a scan to a file.

        Args:
            scan_id: ID of the completed scan
        """
        scan_info = self.active_scans.get(scan_id)
        if not scan_info:
            return
        output_content = {
            "scan_id": scan_id,
            "config": scan_info.get('config', {}),
            "output": scan_info.get('stdout_buffer', ''),
            "stderr": scan_info.get('stderr_buffer', ''),
            "status": scan_info.get('status', 'unknown'),
            "duration_seconds": scan_info.get('duration', 0),
            "completed_at": time.time()
        }

        try:
            with open(scan_info['output_path'], 'w') as f:
                json.dump(output_content, f, indent=2)
        except Exception as e:
            # Don't fail the entire process if file write fails
            print(f"Warning: Could not save scan output to file: {e}")

    async def get_status(self, scan_id: str) -> Dict[str, Any]:
        """
        Get the current status of a running scan.

        Args:
            scan_id: ID of the scan to check

        Returns:
            Dictionary with status information
        """
        if scan_id not in self.active_scans:
            if scan_id in self.completed_scans:
                return {
                    'scan_id': scan_id,
                    'status': 'completed',
                    'message': 'Scan has completed'
                }
            return {
                'scan_id': scan_id,
                'status': 'not_found',
                'error': f"No scan found with name '{scan_id}'"
            }

        scan_info = self.active_scans[scan_id]
        status = scan_info.get('status', 'unknown')
        uptime = time.time() - scan_info.get('start_time', time.time())
        hrs, rem = divmod(int(uptime), 3600)
        mins, secs = divmod(rem, 60)

        return {
            'scan_id': scan_id,
            'status': status,
            'started': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_info.get('start_time', 0))),
            'runtime': f"{hrs}h {mins}m {secs}s",
            'command': scan_info.get('cmd', 'unknown'),
            'targets': scan_info.get('config', {}).get('targets', [])
        }

    async def get_findings(self, scan_id: str, limit: int = 10) -> List[str]:
        """
        Retrieve scanned findings/events from a completed scan.

        Reads the saved output JSON file and returns findings as formatted strings.

        Args:
            scan_id: ID of the completed scan
            limit: Maximum number of findings to return

        Returns:
            List of finding strings
        """
        output_path = os.path.join(self.output_dir, f"{scan_id}.json")
        if not os.path.exists(output_path):
            # Check completed scans info
            if scan_id in self.completed_scans:
                return ["Scan completed — no output file found. Check BBOT CLI output."]
            return []

        try:
            with open(output_path, 'r') as f:
                data = json.load(f)

            output_text = data.get('output', '')
            stderr_text = data.get('stderr', '')

            findings = []
            for line in (output_text + '\n' + stderr_text).split('\n'):
                line = line.strip()
                if line:
                    findings.append(line)

            return findings[-limit:]
        except Exception as e:
            return [f"Error reading scan output: {str(e)}"]

    async def list_active_scans(self) -> List[Dict[str, Any]]:
        """
        List all currently active scans.

        Returns:
            List of scan summaries
        """
        return [
            {
                'scan_id': info['id'],
                'status': info.get('status', 'unknown'),
                'targets': info.get('config', {}).get('targets', []),
                'started': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info.get('start_time', time.time())))
            }
            for scan_id, info in self.active_scans.items()
        ]