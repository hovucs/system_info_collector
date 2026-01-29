#!/usr/bin/env python3
"""
BMC Redfish system information collector.

Usage examples:
  python3 bmc_sys_info_checker.py --bmc 192.0.2.10 --username root --password calvin
  python3 bmc_sys_info_checker.py --bmc https://bmc.example.com --username admin --password pass --out bmc.json --insecure

The script crawls the Redfish service root (/redfish/v1) and follows all
`@odata.id` links and members to collect as many resources as possible.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from typing import Any, Dict, Iterable, List, Optional, Set

import requests
import urllib3


class RedfishCollector:
    def __init__(self, base_url: str, username: Optional[str] = None, password: Optional[str] = None,
                 verify: bool = True, use_session: bool = True, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify = verify
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify
        self.headers: Dict[str, str] = {"Accept": "application/json"}
        self.session_location: Optional[str] = None
        self.use_session = use_session

    def _make_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if path.startswith("/"):
            return f"{self.base_url}{path}"
        return f"{self.base_url}/{path}"

    def login(self) -> None:
        if not self.username or not self.password:
            return
        if not self.use_session:
            # Use basic auth by default
            self.session.auth = (self.username, self.password)
            return

        url = self._make_url("/redfish/v1/Sessions")
        payload = {"UserName": self.username, "Password": self.password}
        try:
            r = self.session.post(url, json=payload, timeout=self.timeout, verify=self.verify)
        except Exception:
            # fall back to basic auth
            self.session.auth = (self.username, self.password)
            return

        if r.status_code in (200, 201):
            token = r.headers.get("X-Auth-Token") or (r.json().get("Id") if r.headers.get("Content-Type","/").startswith("application/json") else None)
            if token:
                self.headers["X-Auth-Token"] = token
            # Sessions resource location
            loc = r.headers.get("Location")
            if loc:
                self.session_location = loc
        else:
            # fallback to basic auth
            self.session.auth = (self.username, self.password)

    def logout(self) -> None:
        if self.session_location:
            try:
                self.session.delete(self._make_url(self.session_location), headers=self.headers, timeout=self.timeout)
            except Exception:
                pass

    def get(self, path: str) -> Optional[Dict[str, Any]]:
        url = self._make_url(path)
        try:
            r = self.session.get(url, headers=self.headers, timeout=self.timeout)
            if r.status_code == 200:
                try:
                    return r.json()
                except ValueError:
                    return None
            else:
                return None
        except requests.RequestException:
            return None

    def collect_firmware_and_hardware(self) -> Dict[str, Any]:
        versions = {}
        # Collect specific resources
        paths = [
            "/redfish/v1",
            "/redfish/v1/Systems",
            "/redfish/v1/Chassis",
            "/redfish/v1/UpdateService",
            "/redfish/v1/UpdateService/FirmwareInventory",
            "/redfish/v1/Chassis/HPM/Thermal"
        ]
        for path in paths:
            data = self.get(path)
            if data:
                versions[path] = data

        # Extract versions
        extracted = {}
        # BMC firmware
        if "/redfish/v1/UpdateService/FirmwareInventory" in versions:
            fw_inv = versions["/redfish/v1/UpdateService/FirmwareInventory"]
            if "Members" in fw_inv:
                for member in fw_inv["Members"]:
                    if "@odata.id" in member:
                        fw_data = self.get(member["@odata.id"])
                        if fw_data and "Version" in fw_data:
                            fw_id = fw_data.get("Id", "").lower()
                            desc = fw_data.get("Description", "").lower()
                            related = fw_data.get("RelatedItem", [])
                            is_bmc = "bmc" in fw_id or "bmc" in desc or any("/Managers/bmc" in str(item) for item in related if isinstance(item, dict))
                            if "bios" in fw_id or "bios" in desc:
                                extracted["BIOS"] = fw_data["Version"]
                            elif is_bmc:
                                extracted["BMC Firmware"] = fw_data["Version"]
                            elif "fpga" in fw_id or "fpga" in desc:
                                extracted["FPGA"] = fw_data["Version"]
                            elif "vr" in fw_id or "vr" in desc:
                                if "VRBundle" in fw_data:
                                    vr_dict = {}
                                    for vr in fw_data["VRBundle"]:
                                        slave = vr.get("SlaveAddress")
                                        fw_ver = vr.get("FirmwareVersion")
                                        if slave and fw_ver and fw_ver != "Unknown":
                                            vr_dict[slave] = fw_ver
                                    if vr_dict:
                                        vr_dict["version"] = fw_data.get("Version", "Unknown")
                                        extracted["VR"] = vr_dict
                                else:
                                    extracted["VR"] = fw_data["Version"]
                            # else: skip unknown firmware

        # BIOS
        if "/redfish/v1/Systems" in versions:
            systems = versions["/redfish/v1/Systems"]
            if "Members" in systems:
                for member in systems["Members"]:
                    if "@odata.id" in member:
                        sys_data = self.get(member["@odata.id"])
                        if sys_data:
                            bios_ver = sys_data.get("BiosVersion")
                            if bios_ver:
                                extracted["BIOS"] = bios_ver

        # FPGA and VR from Chassis
        if "/redfish/v1/Chassis" in versions:
            chassis = versions["/redfish/v1/Chassis"]
            if "Members" in chassis:
                for member in chassis["Members"]:
                    if "@odata.id" in member:
                        ch_data = self.get(member["@odata.id"])
                        if ch_data:
                            # Look for firmware in chassis
                            if "Oem" in ch_data and "AMD" in ch_data["Oem"]:
                                amd_oem = ch_data["Oem"]["AMD"]
                                if "FPGA" in amd_oem:
                                    extracted["FPGA"] = amd_oem["FPGA"]
                                if "VR" in amd_oem:
                                    extracted["VR"] = amd_oem["VR"]

        # Drives
        drives = []
        # Try common storage unit paths that have Drives array
        storage_unit_paths = ["/redfish/v1/Systems/system/Storage/1"]
        for path in storage_unit_paths:
            stor_data = self.get(path)
            if stor_data and "Drives" in stor_data and isinstance(stor_data["Drives"], list):
                for drive_link in stor_data["Drives"]:
                    if "@odata.id" in drive_link:
                        drive_data = self.get(drive_link["@odata.id"])
                        if drive_data:
                            drive_info = {
                                "Model": drive_data.get("Model"),
                                "SerialNumber": drive_data.get("SerialNumber"),
                                "Firmware": drive_data.get("Revision"),
                                "Manufacturer": drive_data.get("Manufacturer"),
                                "MediaType": drive_data.get("MediaType")
                            }
                            drives.append(drive_info)

        # Chassis info
        chassis_info = {}
        thermal_info = {}
        if "/redfish/v1/Chassis" in versions:
            chassis = versions["/redfish/v1/Chassis"]
            if "Members" in chassis:
                for member in chassis["Members"]:
                    if "@odata.id" in member:
                        ch_data = self.get(member["@odata.id"])
                        if ch_data:
                            chassis_info = {
                                "Manufacturer": ch_data.get("Manufacturer"),
                                "Model": ch_data.get("Model"),
                                "SerialNumber": ch_data.get("SerialNumber"),
                                "PartNumber": ch_data.get("PartNumber"),
                                "ChassisType": ch_data.get("ChassisType")
                            }
                            break  # assume one main chassis

        # Direct thermal collection
        thermal_info = {}
        thermal_paths = ["/redfish/v1/Chassis/HPM/Thermal", "/redfish/v1/Chassis/chassis/Thermal"]
        for path in thermal_paths:
            thermal_data = self.get(path)
            if thermal_data:
                fans = []
                if "Fans" in thermal_data and isinstance(thermal_data["Fans"], list):
                    for fan in thermal_data["Fans"]:
                        if "Name" in fan and "Reading" in fan:
                            fans.append({
                                "Name": fan["Name"],
                                "Reading": fan["Reading"],
                                "ReadingUnits": fan.get("ReadingUnits", "RPM")
                            })
                temperatures = []
                if "Temperatures" in thermal_data and isinstance(thermal_data["Temperatures"], list):
                    for temp in thermal_data["Temperatures"]:
                        if "Name" in temp and "ReadingCelsius" in temp:
                            temperatures.append({
                                "Name": temp["Name"],
                                "ReadingCelsius": temp["ReadingCelsius"]
                            })
                if fans or temperatures:
                    thermal_info = {"Fans": fans, "Temperatures": temperatures}
                    break  # use the first one found

        return {"firmware": extracted, "chassis": chassis_info, "drives": drives, "thermal": thermal_info}

    @staticmethod
    def _extract_odata_links(obj: Dict[str, Any]) -> Iterable[str]:
        links: List[str] = []
        for k, v in obj.items():
            if isinstance(v, dict):
                if "@odata.id" in v and isinstance(v["@odata.id"], str):
                    links.append(v["@odata.id"])
                else:
                    links.extend(RedfishCollector._extract_odata_links(v))
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and "@odata.id" in item:
                        links.append(item["@odata.id"])
        return links

    @staticmethod
    def _find_members(obj: Dict[str, Any]) -> List[Any]:
        members = []
        if "Members" in obj and isinstance(obj["Members"], list):
            members.extend(obj["Members"])
        # some implementations have Member arrays under different keys
        for v in obj.values():
            if isinstance(v, dict):
                if "Members" in v and isinstance(v["Members"], list):
                    members.extend(v["Members"])
        return members


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collect Redfish BMC firmware, BIOS, FPGA, VR versions")
    p.add_argument("--bmc", required=True, help="BMC host or base URL (e.g. 192.0.2.10 or https://bmc.example.com)")
    p.add_argument("--u", default="root", help="username for BMC")
    p.add_argument("--p", default="0penBmc", help="password for BMC")
    p.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    p.add_argument("--no-session", dest="use_session", action="store_false", help="do not create Redfish session; use basic auth")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    base = args.bmc
    # normalize base URL: if no scheme assume https
    if not base.startswith("http://") and not base.startswith("https://"):
        base = f"https://{base}"

    collector = RedfishCollector(base_url=base, username=args.u, password=args.p,
                                 verify=(not args.insecure), use_session=args.use_session,
                                 timeout=args.timeout)
    try:
        collector.login()
        data = collector.collect_firmware_and_hardware()
    finally:
        collector.logout()

    print(json.dumps({"base_url": base, "Chassis": data["chassis"], "firmware versions": data["firmware"], "Drives": data["drives"], "Thermal": data["thermal"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
