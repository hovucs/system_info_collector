from contextlib import contextmanager
import shlex
import socket
try:
    import paramiko
except Exception:
    paramiko = None


class OSChecker:
    def __init__(self, **kwargs):
        self.bmc_hostname = kwargs.get('bmc_hostname', None)
        self.bmc_username = 'root'
        self.bmc_password = '0penBmc'
        self.os_hostname = 'spg-' + self.bmc_hostname if self.bmc_hostname else ''
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
            raise ValueError("OS hostname is required to fetch CPU info")
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
            raise ValueError("OS hostname is required to fetch memory info")

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
            raise ValueError("OS hostname is required to fetch disk info")

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
            raise ValueError("OS hostname is required to fetch PCI info")

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

        def _normalize_addr(addr):
            if addr.startswith("0000:"):
                return addr
            return f"0000:{addr}"

        def _parse_verbose(output):
            blocks = {}
            current_addr = ""
            current_lines = []
            for line in output.splitlines():
                if line and not line.startswith("\t") and not line.startswith(" "):
                    if current_addr:
                        blocks[current_addr] = "\n".join(current_lines).strip()
                    current_lines = [line]
                    current_addr = line.split()[0]
                else:
                    if current_lines is not None:
                        current_lines.append(line)
            if current_addr:
                blocks[current_addr] = "\n".join(current_lines).strip()
            return blocks

        def _parse_lspci_verbose(text):
            data = {
                "product_name": "",
                "part_number": "",
                "serial": "",
                "vendor_specific": "",
                "kernel_driver": "",
                "kernel_modules": "",
                "numa_node": "",
                "iommu_group": "",
                "lnkcap": "",
                "lnksta": "",
            }
            vendor_specifics = []
            for raw_line in text.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                if line.startswith("[") and "]" in line:
                    line = line.split("]", 1)[1].strip()
                if line.startswith("Product Name:"):
                    data["product_name"] = line.split(":", 1)[1].strip()
                    continue
                if line.startswith("Part number:"):
                    data["part_number"] = line.split(":", 1)[1].strip()
                    continue
                if line.startswith("Serial number:"):
                    data["serial"] = line.split(":", 1)[1].strip()
                    continue
                if line.startswith("Vendor specific:"):
                    vendor_specifics.append(line.split(":", 1)[1].strip())
                    continue
                if line.startswith("Kernel driver in use:"):
                    data["kernel_driver"] = line.split(":", 1)[1].strip()
                    continue
                if line.startswith("Kernel modules:"):
                    data["kernel_modules"] = line.split(":", 1)[1].strip()
                    continue
                if line.startswith("NUMA node:"):
                    data["numa_node"] = line.split(":", 1)[1].strip()
                    continue
                if line.startswith("IOMMU group:"):
                    data["iommu_group"] = line.split(":", 1)[1].strip()
                    continue
                if "LnkCap:" in line:
                    data["lnkcap"] = line.split("LnkCap:", 1)[1].strip()
                    continue
                if "LnkSta:" in line:
                    data["lnksta"] = line.split("LnkSta:", 1)[1].strip()
                    continue

            vendor_specific = ""
            for value in vendor_specifics:
                if "PCIe" in value or "PCI" in value:
                    vendor_specific = value
                    break
            if not vendor_specific and vendor_specifics:
                vendor_specific = vendor_specifics[0]
            data["vendor_specific"] = vendor_specific
            return data

        def _run_pci(active_conn):
            sudo_prefix = (
                "echo '" + self.os_password.replace("'", "'\\''") + "' | "
                "sudo -S -p '' "
            )
            output = _run_cmd(active_conn, f"{sudo_prefix}lspci -D -nn")
            if not output:
                return

            verbose_output = _run_cmd(active_conn, f"{sudo_prefix}lspci -vvv -nn")
            verbose_blocks = _parse_verbose(verbose_output) if verbose_output else {}

            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(" ", 1)
                address = parts[0]
                summary = parts[1] if len(parts) > 1 else ""
                full_addr = _normalize_addr(address)

                iface = _run_cmd(
                    active_conn,
                    f"ls /sys/bus/pci/devices/{full_addr}/net 2>/dev/null | head -n 1"
                )

                speed = ""
                duplex = ""
                driver = ""
                firmware = ""
                ip_address = ""
                mac_address = ""
                if iface:
                    speed = _run_cmd(active_conn, f"cat /sys/class/net/{iface}/speed 2>/dev/null")
                    ethtool_link = _run_cmd(active_conn, f"ethtool {iface} 2>/dev/null")
                    for link_line in ethtool_link.splitlines():
                        if link_line.strip().startswith("Duplex:"):
                            duplex = link_line.split(":", 1)[1].strip()
                    ethtool_info = _run_cmd(active_conn, f"ethtool -i {iface} 2>/dev/null")
                    for info_line in ethtool_info.splitlines():
                        if info_line.startswith("driver:"):
                            driver = info_line.split(":", 1)[1].strip()
                        if info_line.startswith("firmware-version:"):
                            firmware = info_line.split(":", 1)[1].strip()
                    ip_out = _run_cmd(
                        active_conn,
                        f"ip -o -4 addr show dev {iface} 2>/dev/null | awk '{{print $4}}'"
                    )
                    if ip_out:
                        ip_address = ip_out.split()[0].split("/", 1)[0]
                    mac_address = _run_cmd(active_conn, f"cat /sys/class/net/{iface}/address 2>/dev/null")

                details = ""
                lnkcap = ""
                lnksta = ""
                product_name = ""
                part_number = ""
                serial = ""
                vendor_specific = ""
                kernel_driver = ""
                kernel_modules = ""
                numa_node = ""
                iommu_group = ""
                if verbose_blocks:
                    details = verbose_blocks.get(full_addr) or verbose_blocks.get(address) or ""
                    parsed_verbose = _parse_lspci_verbose(details) if details else {}
                    product_name = parsed_verbose.get("product_name", "")
                    part_number = parsed_verbose.get("part_number", "")
                    serial = parsed_verbose.get("serial", "")
                    vendor_specific = parsed_verbose.get("vendor_specific", "")
                    kernel_driver = parsed_verbose.get("kernel_driver", "")
                    kernel_modules = parsed_verbose.get("kernel_modules", "")
                    numa_node = parsed_verbose.get("numa_node", "")
                    iommu_group = parsed_verbose.get("iommu_group", "")
                    lnkcap = parsed_verbose.get("lnkcap", "")
                    lnksta = parsed_verbose.get("lnksta", "")

                if not details:
                    detail_out = _run_cmd(active_conn, f"{sudo_prefix}lspci -vvv -s {address}")
                    if detail_out:
                        details = detail_out
                        parsed_verbose = _parse_lspci_verbose(detail_out)
                        product_name = product_name or parsed_verbose.get("product_name", "")
                        part_number = part_number or parsed_verbose.get("part_number", "")
                        serial = serial or parsed_verbose.get("serial", "")
                        vendor_specific = vendor_specific or parsed_verbose.get("vendor_specific", "")
                        kernel_driver = kernel_driver or parsed_verbose.get("kernel_driver", "")
                        kernel_modules = kernel_modules or parsed_verbose.get("kernel_modules", "")
                        numa_node = numa_node or parsed_verbose.get("numa_node", "")
                        iommu_group = iommu_group or parsed_verbose.get("iommu_group", "")
                        lnkcap = lnkcap or parsed_verbose.get("lnkcap", "")
                        lnksta = lnksta or parsed_verbose.get("lnksta", "")

                if kernel_driver and not driver:
                    driver = kernel_driver

                results.append({
                    "address": address,
                    "summary": summary,
                    "details": details,
                    "iface": iface,
                    "speed": speed,
                    "duplex": duplex,
                    "driver": driver,
                    "firmware": firmware,
                    "serial": serial,
                    "part_number": part_number,
                    "product_name": product_name,
                    "vendor_specific": vendor_specific,
                    "kernel_driver": kernel_driver,
                    "kernel_modules": kernel_modules,
                    "numa_node": numa_node,
                    "iommu_group": iommu_group,
                    "ip_address": ip_address,
                    "mac": mac_address,
                    "lnkcap": lnkcap,
                    "lnksta": lnksta,
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
    
    