from contextlib import contextmanager
import shlex
import socket
try:
    import paramiko
except Exception:
    paramiko = None


class OSChecker:
    def __init__(self, bmc_hostname=None, **kwargs):
        self.bmc_hostname = bmc_hostname
        self.bmc_username = 'root'
        self.bmc_password = '0penBmc'
        self.os_hostname = 'spg-' + bmc_hostname if bmc_hostname else ''
        self.os_username = 'amd'
        self.os_password = 'amd123'
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
            raise ImportError("paramiko is required for SSH connections")

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

    def get_info(self, conn=None):
        """Run OS commands over SSH and return basic system info."""
        if not self.os_hostname:
            raise ValueError("os_hostname is required to fetch OS info")

        def _read_channel(channel):
            try:
                data = channel.read()
            except Exception:
                return ""
            if isinstance(data, bytes):
                return data.decode(errors="ignore").strip()
            return str(data).strip()

        commands = {
            "OS": "cat /etc/os-release | grep PRETTY_NAME= | cut -d= -f2 | tr -d '\"'",
            "Kernel": "uname -r",
            "cmdline": "cat /proc/cmdline",
            "ip": "hostname -I | awk '{print $1}'",
            "BIOS": "cat /sys/class/dmi/id/bios_vendor /sys/class/dmi/id/bios_version 2>/dev/null | xargs",
        }

        results = {
            "bmc_hostname": self.bmc_hostname,
            "bmc_username": self.bmc_username,
            "bmc_password": self.bmc_password,
            "os_hostname": self.os_hostname,
            "os_username": self.os_username,
            "os_password": self.os_password,
        }

        def _run_commands(active_conn):
            for key, cmd in commands.items():
                _, stdout, stderr = active_conn.exec_command(cmd)
                value = _read_channel(stdout)
                if not value:
                    value = _read_channel(stderr)
                results[key] = value

        if conn is None:
            with self.ssh_connection(
                self.os_hostname,
                self.os_username,
                self.os_password
            ) as active_conn:
                _run_commands(active_conn)
        else:
            _run_commands(conn)

        return results

    def get_cpu(self, conn=None):
        """Return a dictionary with CPU information."""
        if not self.os_hostname:
            raise ValueError("os_hostname is required to fetch CPU info")

        def _read_channel(channel):
            try:
                data = channel.read()
            except Exception:
                return ""
            if isinstance(data, bytes):
                return data.decode(errors="ignore").strip()
            return str(data).strip()

        def _parse_lscpu(text):
            values = {}
            for line in text.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    values[key.strip()] = val.strip()
            return values

        results = {
            "CPU(s)": "",
            "On-line CPU(s) list": "",
            "Model name": "",
            "Thread(s) per core": "",
            "Core(s) per socket": "",
            "Socket(s)": "",
            "CPU(s) scaling MHz": "",
            "CPU max MHz": "",
            "CPU min MHz": "",
            "BogoMIPS": "",
            "Architecture": "",
        }

        def _run_cpu(active_conn):
            _, stdout, stderr = active_conn.exec_command("lscpu")
            lscpu_out = _read_channel(stdout)
            if not lscpu_out:
                lscpu_out = _read_channel(stderr)
            lscpu_vals = _parse_lscpu(lscpu_out) if lscpu_out else {}

            results["Architecture"] = lscpu_vals.get("Architecture", "")
            results["CPU(s)"] = lscpu_vals.get("CPU(s)", "")
            results["On-line CPU(s) list"] = lscpu_vals.get("On-line CPU(s) list", "")
            results["Model name"] = lscpu_vals.get("Model name", "")
            results["Socket(s)"] = lscpu_vals.get("Socket(s)", "")
            results["Thread(s) per core"] = lscpu_vals.get("Thread(s) per core", "")
            results["Core(s) per socket"] = lscpu_vals.get("Core(s) per socket", "")
            results["CPU(s) scaling MHz"] = lscpu_vals.get("CPU MHz", "")
            results["CPU max MHz"] = lscpu_vals.get("CPU max MHz", "")
            results["CPU min MHz"] = lscpu_vals.get("CPU min MHz", "")
            results["BogoMIPS"] = lscpu_vals.get("BogoMIPS", "")

            for key, value in lscpu_vals.items():
                if key == "NUMA node(s)":
                    results[key] = value
                if key.startswith("NUMA node") and key.endswith("CPU(s)"):
                    results[key] = value
                if key.endswith("cache") and key[:1].upper() == "L":
                    results[key] = value

            if not results["Model name"] or not results["CPU(s) scaling MHz"] or not results["BogoMIPS"]:
                _, stdout, _ = active_conn.exec_command("cat /proc/cpuinfo")
                cpuinfo = _read_channel(stdout)
                if cpuinfo:
                    for line in cpuinfo.splitlines():
                        low = line.lower()
                        if not results["Model name"] and low.startswith("model name"):
                            results["Model name"] = line.split(":", 1)[1].strip()
                        if not results["CPU(s) scaling MHz"] and low.startswith("cpu mhz"):
                            results["CPU(s) scaling MHz"] = f"{line.split(':', 1)[1].strip()} MHz"
                        if not results["BogoMIPS"] and low.startswith("bogomips"):
                            results["BogoMIPS"] = line.split(":", 1)[1].strip()
                        if results["Model name"] and results["CPU(s) scaling MHz"] and results["BogoMIPS"]:
                            break

        if conn is None:
            with self.ssh_connection(
                self.os_hostname,
                self.os_username,
                self.os_password
            ) as active_conn:
                _run_cpu(active_conn)
        else:
            _run_cpu(conn)

        return results
    
    def get_memory(self, conn=None):
        """Return a dictionary with memory information."""
        if not self.os_hostname:
            raise ValueError("os_hostname is required to fetch memory info")

        def _read_channel(channel):
            try:
                data = channel.read()
            except Exception:
                return ""
            if isinstance(data, bytes):
                return data.decode(errors="ignore").strip()
            return str(data).strip()

        def _parse_meminfo(text):
            values = {}
            for line in text.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    values[key.strip()] = val.strip()
            return values

        results = {
            "Total": "",
            "Available": "",
            "Used": "",
            "DIMMs": [],
        }

        def _parse_dmidecode(text):
            dimms = []
            current = None
            for line in text.splitlines():
                if line.startswith("Memory Device"):
                    if current:
                        dimms.append(current)
                    current = {}
                    continue
                if current is None:
                    continue
                if ":" in line:
                    key, val = line.split(":", 1)
                    current[key.strip()] = val.strip()
            if current:
                dimms.append(current)
            return dimms

        def _run_memory(active_conn):
            sudo_cmd = (
                "echo '" + self.os_password.replace("'", "'\\''") + "' | "
                "sudo -S -p '' dmidecode -t 17"
            )
            _, stdout, stderr = active_conn.exec_command(sudo_cmd)
            dmi_out = _read_channel(stdout)
            if not dmi_out:
                dmi_out = _read_channel(stderr)
            dimms = _parse_dmidecode(dmi_out) if dmi_out else []
            results["DIMMs"] = dimms

            _, stdout, _ = active_conn.exec_command("cat /proc/meminfo")
            meminfo = _read_channel(stdout)
            values = _parse_meminfo(meminfo) if meminfo else {}
            total = values.get("MemTotal", "")
            available = values.get("MemAvailable", "")
            results["Total"] = total
            results["Available"] = available

            try:
                total_kb = int(total.split()[0])
                available_kb = int(available.split()[0])
                used_kb = total_kb - available_kb
                results["Used"] = f"{used_kb} kB"
            except Exception:
                results["Used"] = ""

        if conn is None:
            with self.ssh_connection(
                self.os_hostname,
                self.os_username,
                self.os_password
            ) as active_conn:
                _run_memory(active_conn)
        else:
            _run_memory(conn)

        return results
    
    def get_disk(self, conn=None):
        """Return a dictionary with disk information."""
        if not self.os_hostname:
            raise ValueError("os_hostname is required to fetch disk info")

        def _read_channel(channel):
            try:
                data = channel.read()
            except Exception:
                return ""
            if isinstance(data, bytes):
                return data.decode(errors="ignore").strip()
            return str(data).strip()

        results = {
            "Total": "",
            "Used": "",
            "Free": "",
            "Devices": [],
        }

        def _run_disk(active_conn):
            _, stdout, _ = active_conn.exec_command("df -k --total | tail -1")
            df_out = _read_channel(stdout)
            if df_out:
                parts = df_out.split()
                if len(parts) >= 5:
                    total_kb = parts[1]
                    used_kb = parts[2]
                    free_kb = parts[3]
                    results["Total"] = f"{total_kb} kB"
                    results["Used"] = f"{used_kb} kB"
                    results["Free"] = f"{free_kb} kB"

            _, stdout, stderr = active_conn.exec_command(
                "lsblk -b -o NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE,MODEL,SERIAL,PKNAME -P"
            )
            lsblk_out = _read_channel(stdout)
            if not lsblk_out:
                lsblk_out = _read_channel(stderr)

            if lsblk_out:
                devices = []
                pkname_map = {}
                raw_entries = []
                for line in lsblk_out.splitlines():
                    entry = {}
                    for pair in shlex.split(line):
                        if "=" in pair:
                            key, val = pair.split("=", 1)
                            entry[key] = val.strip('"')
                    if entry:
                        raw_entries.append(entry)
                        name = entry.get("NAME", "")
                        dtype = entry.get("TYPE", "")
                        pkname = entry.get("PKNAME", "")
                        if dtype == "disk" and name:
                            pkname_map[name] = name
                        elif name and pkname:
                            pkname_map[name] = pkname

                _, stdout, _ = active_conn.exec_command("df -kP")
                df_all_kb = _read_channel(stdout)
                disk_usage = {}
                if df_all_kb:
                    lines = df_all_kb.splitlines()
                    for line in lines[1:]:
                        parts = line.split()
                        if len(parts) >= 6:
                            filesystem = parts[0]
                            if not filesystem.startswith("/dev/"):
                                continue
                            used_kb = parts[2]
                            avail_kb = parts[3]
                            dev_name = filesystem.rsplit("/", 1)[-1]
                            disk_name = pkname_map.get(dev_name, dev_name)
                            disk_usage.setdefault(disk_name, {"Used": 0, "Available": 0})
                            try:
                                disk_usage[disk_name]["Used"] += int(used_kb)
                                disk_usage[disk_name]["Available"] += int(avail_kb)
                            except Exception:
                                continue

                for entry in raw_entries:
                    name = entry.get("NAME", "")
                    dtype = entry.get("TYPE", "")
                    device = {
                        "Name": name,
                        "Size": entry.get("SIZE", ""),
                        "Type": dtype,
                        "Mount": entry.get("MOUNTPOINT", ""),
                        "FSType": entry.get("FSTYPE", ""),
                        "Model": entry.get("MODEL", ""),
                        "Serial": entry.get("SERIAL", ""),
                        "Used": "",
                        "Available": "",
                    }
                    disk_name = pkname_map.get(name, name)
                    usage = disk_usage.get(disk_name)
                    if usage and dtype == "disk":
                        device["Used"] = f"{usage['Used']} kB"
                        device["Available"] = f"{usage['Available']} kB"
                    devices.append(device)
                results["Devices"] = devices

        if conn is None:
            with self.ssh_connection(
                self.os_hostname,
                self.os_username,
                self.os_password
            ) as active_conn:
                _run_disk(active_conn)
        else:
            _run_disk(conn)

        return results
    
    def get_pci(self, conn=None):
        """Return a list with PCI device information."""
        if not self.os_hostname:
            raise ValueError("os_hostname is required to fetch PCI info")

        def _read_channel(channel):
            try:
                data = channel.read()
            except Exception:
                return ""
            if isinstance(data, bytes):
                return data.decode(errors="ignore").strip()
            return str(data).strip()

        def _run_cmd(active_conn, cmd):
            _, stdout, stderr = active_conn.exec_command(cmd)
            out = _read_channel(stdout)
            if not out:
                out = _read_channel(stderr)
            return out

        results = []

        def _run_pci(active_conn):
            output = _run_cmd(active_conn, "lspci -nn")
            if not output:
                return

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(" ", 1)
                address = parts[0]
                summary = parts[1] if len(parts) > 1 else ""
                full_addr = address
                if not address.startswith("0000:"):
                    full_addr = f"0000:{address}"

                device_info = {}
                for key, path in {
                    "vendor": "vendor",
                    "device": "device",
                    "subsystem_vendor": "subsystem_vendor",
                    "subsystem_device": "subsystem_device",
                    "class": "class",
                    "revision": "revision",
                }.items():
                    value = _run_cmd(active_conn, f"cat /sys/bus/pci/devices/{full_addr}/{path} 2>/dev/null")
                    if value:
                        device_info[key] = value.strip()

                iface = ""
                iface_list = _run_cmd(active_conn, f"ls -1 /sys/bus/pci/devices/{full_addr}/net 2>/dev/null")
                if iface_list:
                    iface = iface_list.splitlines()[0].strip()

                speed = ""
                driver = ""
                firmware = ""
                serial = ""
                part_number = ""
                vendor_name = ""
                if iface:
                    speed = _run_cmd(active_conn, f"cat /sys/class/net/{iface}/speed 2>/dev/null")
                    ethtool_info = _run_cmd(active_conn, f"ethtool -i {iface} 2>/dev/null")
                    for info_line in ethtool_info.splitlines():
                        if info_line.startswith("driver:"):
                            driver = info_line.split(":", 1)[1].strip()
                        if info_line.startswith("firmware-version:"):
                            firmware = info_line.split(":", 1)[1].strip()
                    udev_props = _run_cmd(active_conn, f"udevadm info -q property -p /sys/class/net/{iface} 2>/dev/null")
                    for prop in udev_props.splitlines():
                        if prop.startswith("ID_SERIAL="):
                            serial = prop.split("=", 1)[1].strip()
                        if prop.startswith("ID_MODEL="):
                            part_number = prop.split("=", 1)[1].strip()
                        if prop.startswith("ID_VENDOR="):
                            vendor_name = prop.split("=", 1)[1].strip()

                sudo_cmd = (
                    "echo '" + self.os_password.replace("'", "'\\''") + "' | "
                    f"sudo -S -p '' lspci -vvv -s {address}"
                )
                details = _run_cmd(active_conn, sudo_cmd)
                lnkcap = ""
                lnksta = ""
                for detail_line in details.splitlines():
                    if "LnkCap:" in detail_line:
                        lnkcap = detail_line.split("LnkCap:", 1)[1].strip()
                    if "LnkSta:" in detail_line:
                        lnksta = detail_line.split("LnkSta:", 1)[1].strip()

                results.append({
                    "address": address,
                    "summary": summary,
                    "details": details,
                    "iface": iface,
                    "speed": speed,
                    "driver": driver,
                    "firmware": firmware,
                    "serial": serial,
                    "part_number": part_number,
                    "vendor": vendor_name,
                    "lnkcap": lnkcap,
                    "lnksta": lnksta,
                    "sysfs": device_info,
                })

        if conn is None:
            with self.ssh_connection(
                self.os_hostname,
                self.os_username,
                self.os_password
            ) as active_conn:
                _run_pci(active_conn)
        else:
            _run_pci(conn)

        return results
    
    