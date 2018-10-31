from __future__ import absolute_import

import re, logging
from sys import stderr
from os import environ
from time import sleep
from requests import Session
# Due to optional requirement
try:
    from bs4 import BeautifulSoup
except ImportError:
   pass

from lexicon.providers.base import Provider as BaseProvider

logger = logging.getLogger(__name__)

NAMESERVER_DOMAINS = ['vdx.nl']

def ProviderParser(subparser):
    subparser.description = """VDX.nl"""
    subparser.add_argument(
        '--auth-username',
        help='specify username for authentication'
    )
    subparser.add_argument(
        '--auth-password',
        help='specify password for authentication',
    )


class Provider(BaseProvider):
    """
        VDX.nl provider
    """

    def __init__(self, options, engine_overrides=None):
        super(Provider, self).__init__(options, engine_overrides)
        self.options = options
        self.domain = self.options['domain']
        self.domain_id = None

    def authenticate(self):
        """
        """
        # Create the session GET the login page to retrieve a session cookie
        self.session = Session()    
        self.session.get(
            "https://mijn.vdx.nl/"
        )

        # Hit the login page with authentication info to login the session
        login_response = self.session.post(
            "https://accounts.vdx.nl/login?service=aHR0cHM6Ly9taWpuLnZkeC5ubC9sb2dpbj9mcm9tPWFjY291bnRz",
            data={
                "username": self.options['auth_username'],
                "password": self.options['auth_password'],
                "action": "login",
                "service": "https://mijn.vdx.nl/login"
            }
        )

        # Parse in the HTML, if the div containing the error message is found, error
        html = BeautifulSoup(login_response.content, "html.parser")
        if html.find("a", {"target": "_parent"}) is not None:
            sso_response = self.session.get(html.find("a", {"target": "_parent"})["href"])
        else:
            logger.warning("VDX.nl login failed, check username and password")
            return False

        # Make an authenticated GET to the DNS management page
        zones_response = self.session.get("https://mijn.vdx.nl/accounts")

        html = BeautifulSoup(zones_response.content, "html.parser")
        
        zone = html.find_all("a", string=self.options.get("domain",''))

        # If the tag couldn't be found, error, otherwise, return the value of the tag
        if zone is None or len(zone) == 0:
            logger.warning("Domain {0} not found in account".format(self.options.get("domain",'')))
            raise AssertionError("Domain {0} not found in account".format(self.options.get("domain",'')))

        self.domain_id = str(zone[-1]["href"].split("/")[-1])
        logger.debug("VDXNL domain ID: {}".format(self.domain_id))
        return True

    # Create record. If record already exists with the same content, do nothing
    def create_record(self, type, name, content):
        logger.debug("Creating record for zone {0}".format(name))
        # Pull a list of records and check for ours
        records = self.list_records(type=type, name=name, content=content)
        if len(records) >= 1:
            logger.warning("Duplicate record {} {} {}, NOOP".format(type, name, content))
            return True
        
        vdxTypeId = 2
        
        if (type == "A"):
            vdxTypeId = 2
        elif (type == "CNAME"):
            vdxTypeId = 3
        elif (type == "MX"):
            vdxTypeId = 4
        elif (type == "TXT"):
            vdxTypeId = 7
        elif (type == "AAAA"):
            vdxTypeId = 8
        elif (type == "SRV"):
            vdxTypeId = 9
        elif (type == "CAA"):
            vdxTypeId = 10

        insert_response = self.session.post(
            "https://mijn.vdx.nl/accounts/{0}/dns/save".format(self.domain_id),
            data={
                "XvalA_1": (name),
                "Xtype_1": str(vdxTypeId),
                "XvalB_1": "",
                "XvalC_1": str(content),
                "Xdel_1": "0"
            }
        )

        # Pull a list of records and check for ours
        records = self.list_records(name=name)
        if len(records) >= 1:
            logger.info("Successfully added record {}".format(name))
            return True
        else:
            logger.info("Failed to add record {}".format(name))
            return False

        return False

    # List all records. Return an empty list if no records found.
    # type, name and content are used to filter records.
    # If possible filter during the query, otherwise filter after response is
    # received.
    def list_records(self, type=None, name=None, content=None, id=None):
        records = []
        # Make an authenticated GET to the DNS management page
        edit_response = self.session.get(
            "https://mijn.vdx.nl/accounts/{0}/dns".format(self.domain_id)
        )

        # Parse the HTML response, and list the table rows for DNS records
        html = BeautifulSoup(edit_response.content, "html.parser")
        records = html.find(id='dnsTbl').find_all('tr')
        new_records = []
        for dns_tr in records:
            tds = dns_tr.findAll("td")
            # Process HTML in the TR children to derive each object
            if tds is None or len(tds) == 0:
                continue

            rec = {}
            if tds[0].find("input"):
                rec['name'] = tds[0].input["value"]
            else:
                rec['name'] = ""

            if tds[1].find("input"):
                rec['id'] = tds[1].input["name"].split("_")[1]
            else:
                rec['id'] = ""
            
            if len(list(tds[1].stripped_strings)) != 0:
                rec['type'] = str(list(tds[1].stripped_strings)[0])
            else:
                rec['type'] = ""

            if tds[3].find("input"):
                rec['content'] = tds[3].input["value"]
            else:
                rec['type'] = ""

            new_records.append(rec)
        records = new_records
        if id:
            logger.debug("Filtering {} records by id: {}".format(len(records), id))
            records = [record for record in records if record['id'] == id]
        if type:
            logger.debug("Filtering {} records by type: {}".format(len(records), type))
            records = [record for record in records if record['type'] == type]
        if name:
            logger.debug("Filtering {} records by name: {}".format(len(records), name))
            if name.endswith('.'):
                name = name[:-1]
            records = [record for record in records if name in record['name'] ]
        if content:
            logger.debug("Filtering {} records by content: {}".format(len(records), content.lower()))
            records = [record for record in records if record['content'].lower() == content.lower()]
        logger.debug("Final records ({}): {}".format(len(records), records))
        return records

    # Create or update a record.
    def update_record(self, identifier, type=None, name=None, content=None):
        # Delete record if it exists
        self.delete_record(identifier, type, name, content)
        return self.create_record(type, name, content)

    # Delete an existing record.
    # If record does not exist, do nothing.
    def delete_record(self, identifier=None, type=None, name=None, content=None):
        delete_record_ids = []
        if not identifier:
            records = self.list_records(type, name, content)
            delete_record_ids = [record['id'] for record in records]
        else:
            delete_record_ids.append(identifier)
        logger.debug("Record IDs to delete: {}".format(delete_record_ids))
        for rec_id in delete_record_ids:
            # POST to the DNS management UI with form values to delete the record
            delete_response = self.session.post(
                "https://mijn.vdx.nl/accounts/{0}/dns/save".format(self.domain_id),
                data={
                    "type_{0}".format(rec_id): "",
                    "valA_{0}".format(rec_id): "",
                    "valB_{0}".format(rec_id): "",
                    "valC_{0}".format(rec_id): "",
                    "del_{0}".format(rec_id): "1"
                }
            )

        return True
