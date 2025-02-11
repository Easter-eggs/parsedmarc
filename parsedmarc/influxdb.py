import requests
import base64
import re

from parsedmarc import logger
from parsedmarc.utils import human_timestamp_to_unix_timestamp


class InfluxDBClient(object):
    """A client for influxdb"""

    def __init__(self, uri, user, password, timeout=60):
        """
        Initializes the InfluxDBClient
        Args:
            uri (str): The influxdb uri
            user (str): The influxdb user
            password (str): The influxdb password
            timeout (int): The timeout to use when accessing influxdb
        """
        self.uri = uri
        self.timeout = timeout
        self.session = requests.Session()
        auth = user+":"+password
        auth_bytes = auth.encode("ascii")
        auth_b64 = base64.b64encode(auth_bytes)
        self.session.headers = {
            "Authorization": "Basic "+auth_b64.decode("ascii")
        }

    def save_aggregate_reports_to_influxdb(self, aggregate_reports):
        """
        Saves aggregate DMARC reports to InfluxDB

        Args:
            aggregate_reports: A list of aggregate report dictionaries
                to save in InfluxDB

        """
        logger.debug("Saving aggregate reports to InfluxDB")
        if isinstance(aggregate_reports, dict):
            aggregate_reports = [aggregate_reports]

        if len(aggregate_reports) < 1:
            return

        for report in aggregate_reports:
            metadata = report["report_metadata"]
            for record in report["records"]:
                influxdb_str = "dmarc_aggregate"
                new_report = dict()
                new_report["xml_schema"] = report["xml_schema"]
                new_report["org_name"] = metadata["org_name"]
                new_report["org_email"] = metadata["org_email"]
                new_report["org_extra_contact_info"] = metadata["org_extra_contact_info"]
                new_report["report_id"] = metadata["report_id"]
                new_report["source_ip_address"] = record["source"]["ip_address"]
                new_report["source_country"] = record["source"]["country"]
                new_report["source_reverse_dns"] = record["source"]["reverse_dns"]
                new_report["source_base_domain"] = record["source"]["base_domain"]
                new_report["source_type"] = record["source"]["type"]
                new_report["source_name"] = record["source"]["name"]
                new_report["disposition"] = record["policy_evaluated"]["disposition"]
                new_report["spf_aligned"] = record["policy_evaluated"]["spf"] is not None and record["policy_evaluated"]["spf"].lower() == "pass"
                new_report["dkim_aligned"] = record["policy_evaluated"]["dkim"] is not None and record["policy_evaluated"]["dkim"].lower() == "pass"
                new_report["passed_dmarc"] = new_report["spf_aligned"] or new_report["dkim_aligned"]
                new_report["header_from"] = record["identifiers"]["header_from"]
                new_report["envelope_from"] = record["identifiers"]["envelope_from"]

                timestamp = human_timestamp_to_unix_timestamp(metadata["begin_date"])
                timestamp_str = f'{timestamp}'
                for key, value in new_report.items():
                    if value != "":
                        value = f'{value}'
                        influxdb_str += ","+key+"="+re.sub(r'([,= ])', r'\\\1', value)
                count = record["count"]
                influxdb_str += " message_count="+f'{count}'+"i"
                influxdb_str += " "+timestamp_str.split(".",1)[0]+"000000000"
                try:
                    self._send_to_influxdb(influxdb_str)
                except Exception as error_:
                    logger.error("InfluxDB Error: {0}".format(error_.__str__()))

    def _send_to_influxdb(self, influxdb_str):
        try:
            self.session.post(self.uri, data=influxdb_str, timeout=self.timeout)
        except Exception as error_:
            logger.error("InfluxDB Error: {0}".format(error_.__str__()))
