from contextlib import contextmanager
import shlex
import socket
try:
    import paramiko
except Exception:
    paramiko = None


class BMCChecker:
    def __init__(self, **kwargs):
        self.bmc_hostname = kwargs.get('bmc_hostname', None)
        self.bmc_username = 'root'
        self.bmc_password = '0penBmc'      
        self.bmc_mac_address = ''
        self.bmc_ip_address = ''
        self.bmc_fw_version = ''
        self.bios = ''
        self.fpga = ''
        self.vr = ''

    @contextmanager
    def ssh_connection(
        self,
        hostname,
        username,
        password,
        port=22,
        timeout=10,
        allow_agent=True,
        look_for_keys=True,
    ):
        """Yield an active SSH connection and always close it."""
        if paramiko is None:
            raise ImportError("paramiko lib is required for SSH connections")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=hostname,
                username=username,
                password=password,
                port=port,
                timeout=timeout,
                allow_agent=allow_agent,
                look_for_keys=look_for_keys,
                banner_timeout=timeout,
                auth_timeout=timeout,
            )
        except (socket.timeout, socket.gaierror) as exc:
            raise ConnectionError(f"SSH connection failed: {exc}") from exc
        except Exception as exc:
            raise ConnectionError(f"SSH connection failed: {exc}") from exc
        try:
            yield client
        finally:
            client.close()

    @staticmethod
    def _read_channel(channel):
        try:
            data = channel.read()
        except Exception:
            return ""
        if isinstance(data, bytes):
            return data.decode(errors="ignore").strip()
        return str(data).strip()

    def _run_command(self, conn, cmd, use_shell=False):
        exec_cmd = cmd
        if use_shell:
            exec_cmd = f"sh -c {shlex.quote(cmd)}"
        _, stdout, stderr = conn.exec_command(exec_cmd)
        return self._read_channel(stdout), self._read_channel(stderr)

    def _require_bmc(self):
        if not self.bmc_hostname:
            raise ValueError("bmc_hostname is required")

    def get_temperatures(self):
        self._require_bmc()

        temp_cmds = {
            "cpu0": "cat /sys/devices/platform/soc@14000000/14c24000.i3c4/14c24000.i3c4/4-118/hwmon/**/temp1_input",
            "dimm0": "cat /sys/devices/platform/soc@14000000/14c24000.i3c4/14c24000.i3c4/4-1118/hwmon/**/temp*_input",
            "cpu1": "cat /sys/devices/platform/soc@14000000/14c25000.i3c5/14c25000.i3c5/5-1000118/hwmon/**/temp1_input",
            "dimm1": "cat /sys/devices/platform/soc@14000000/14c25000.i3c5/14c25000.i3c5/5-1001118/hwmon/**/temp*_input",
        }

        def _parse_values(text):
            values = []
            for line in text.splitlines():
                for token in line.split():
                    if token.lstrip("-").isdigit():
                        values.append(int(token))
            return values

        results = {"cpu0": [], "dimm0": [], "cpu1": [], "dimm1": []}

        with self.ssh_connection(
            self.bmc_hostname,
            self.bmc_username,
            self.bmc_password,
        ) as conn:
            for key, cmd in temp_cmds.items():
                out, err = self._run_command(conn, cmd, use_shell=True)
                if not out and err and "No such file or directory" in err:
                    continue
                if out:
                    results[key] = _parse_values(out)

        return results

    def check_bmc(self):
        self._require_bmc()

        def _parse_key_values(text):
            data = {}
            for line in text.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                data[key.strip()] = value.strip()
            return data

        with self.ssh_connection(
            self.bmc_hostname,
            self.bmc_username,
            self.bmc_password,
        ) as conn:
            fru_out, fru_err = self._run_command(conn, "ipmitool fru print")
            if not fru_out:
                fru_out = fru_err

            env_out, env_err = self._run_command(conn, "fw_printenv")
            if not env_out:
                env_out = env_err

        fru_data = _parse_key_values(fru_out) if fru_out else {}
        env_data = _parse_key_values(env_out) if env_out else {}
        temps = self.get_temperatures()

        summary = {
            "Chassis Type": fru_data.get("Chassis Type", ""),
            "Chassis Serial": fru_data.get("Chassis Serial", ""),
            "Chassis Area Checksum": fru_data.get("Chassis Area Checksum", ""),
            "Board Mfg Date": fru_data.get("Board Mfg Date", ""),
            "Board Mfg": fru_data.get("Board Mfg", ""),
            "Board Product": fru_data.get("Board Product", ""),
            "Board Serial": fru_data.get("Board Serial", ""),
            "Board Part Number": fru_data.get("Board Part Number", ""),
            "Board Area Checksum": fru_data.get("Board Area Checksum", ""),
            "board_id": env_data.get("board_id", ""),
            "board_rev": env_data.get("board_rev", ""),
            "CPU 0 Temp": temps.get("cpu0", []),
            "CPU 1 Temp": temps.get("cpu1", []),
            "DIMM 0 Temp": temps.get("dimm0", []),
            "DIMM 1 Temp": temps.get("dimm1", []),
        }

        return {
            "bmc_hostname": self.bmc_hostname,
            "fru": fru_data,
            "fw_printenv": env_data,
            "temperatures": temps,
            "summary": summary,
        }

    def get_system_info(self):
        """Return parsed output for ipmitool fru print and fw_printenv."""
        data = self.check_bmc()
        return {
            "fru": data.get("fru", {}),
            "fw_printenv": data.get("fw_printenv", {}),
        }
