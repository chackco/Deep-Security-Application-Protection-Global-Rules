import os
import sys
import warnings
import deepsecurity as api
from deepsecurity.rest import ApiException
from pprint import pprint
import json

if not sys.warnoptions:
    warnings.simplefilter('ignore')

RULES_FILENAME = 'rules.csv'


class AppControlRuleSets:
    def __init__(self):
        ds_api_key = os.environ['DS_KEY']
        self.api_version = os.environ.get('DS_API_VERSION', 'v1')
        dsm_address = os.environ.get('DS_API_ADDRESS', 'https://app.deepsecurity.trendmicro.com/api')
        config = api.Configuration()
        config.host = dsm_address
        config.api_key['api-secret-key'] = ds_api_key
        self.api_client = api.ApiClient(config)

    @staticmethod
    def get_unique_rules(existing_rule_hashes, new_rules) -> list:
        """Diff between existing rules and new rules

        Example:

        [['demo_1', '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9011'],
        ['demo_3', '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9033']]

        :param existing_rule_hashes:
        :param new_rules:
        :return: List of lists
        """
        unique_new_rules = []

        print('\nComparing new rules to existing rules...')

        for entry in new_rules:
            rule_hash = entry[1]

            if rule_hash in existing_rule_hashes:
                print(f'Found existing hash: {rule_hash}')

            else:
                print(f'Found new hash ({entry[0]}): {rule_hash}')
                unique_new_rules.append(entry)

        if unique_new_rules:
            print('\nAll new hashes which were found:')
            pprint(unique_new_rules)
            return unique_new_rules

        else:
            print('\nNo new hashes found')
            sys.exit()

    def get_global_rules(self) -> list:
        """List of existing rules

        Example:

        [{'action': 'block',
         'description': '',
         'id': 34,
         'last_updated': 1580783107664,
         'last_updated_administrator': 34,
         'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9069'},
         {'action': 'block',
         'description': 'demo',
         'id': 35,
         'last_updated': 1580783365699,
         'last_updated_administrator': 34,
         'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9068'},
         {'action': 'block',
         'description': 'demo',
         'id': 36,
         'last_updated': 1580783934705,
         'last_updated_administrator': 100,
         'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9022'},
         {'action': 'block',
         'description': 'demo',
         'id': 37,
         'last_updated': 1580784663099,
         'last_updated_administrator': 100,
         'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9023'}]

        :return: List of <class 'deepsecurity.models.application_control_global_rule.ApplicationControlGlobalRule'>
        """

        print('Reading existing rules from Deep Security...')

        try:
            global_rules_api = api.GlobalRulesApi(self.api_client)
            api_response = global_rules_api.list_global_rules(self.api_version)
            extracted_rules = api_response.application_control_global_rules
            pprint(extracted_rules)

            return extracted_rules

        except ApiException as e:
            self._format_exception(e)

    def get_existing_rule_hashes(self, csv_rules) -> list:
        """Extracts hashes from existing rules

        Example:

        ['7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9069',
        '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9068',
        '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9022',
        '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9023']

        :param csv_rules:
        :return: list
        """

        print('\nExtracting hashes from existing rules...')
        hashes = []

        for entry in csv_rules:
            entry_hash = entry.sha256
            hashes.append(entry_hash)

        print('Found the following hashes:')
        pprint(hashes)

        return hashes

    @staticmethod
    def create_global_rule_objects(unique_rules) -> list:
        """Creates a list of of ApplicationControlGlobalRules

        Example:

        [{'action': None,
         'description': 'demo_5',
        'id': None,
        'last_updated': None,
        'last_updated_administrator': None,
        'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9055'}]

        :param unique_rules:
        :return: <class 'deepsecurity.models.application_control_global_rule.ApplicationControlGlobalRule'>
        """

        new_rules = []

        for rule in unique_rules:
            rule_description = rule[0]
            rule_hash = rule[1]

            new_rule = api.ApplicationControlGlobalRule()
            new_rule.description = rule_description
            new_rule.sha256 = rule_hash
            new_rules.append(new_rule)

        return new_rules

    def create_global_rules(self, rules_array) -> api.models.application_control_global_rules.ApplicationControlGlobalRules:
        """Creates global rules on Deep Security

        Example:

            {'application_control_global_rules': [{'action': 'block',
               'description': '',
               'id': 34,
               'last_updated': 1580783107664,
               'last_updated_administrator': 34,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9069'},
              {'action': 'block',
               'description': 'demo',
               'id': 35,
               'last_updated': 1580783365699,
               'last_updated_administrator': 34,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9068'},
              {'action': 'block',
               'description': 'demo',
               'id': 36,
               'last_updated': 1580783934705,
               'last_updated_administrator': 100,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9022'},
              {'action': 'block',
               'description': 'demo',
               'id': 37,
               'last_updated': 1580784663099,
               'last_updated_administrator': 100,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9023'},
              {'action': 'block',
               'description': 'demo_1',
               'id': 67,
               'last_updated': 1580867088483,
               'last_updated_administrator': 100,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9011'},
              {'action': 'block',
               'description': 'demo_3',
               'id': 68,
               'last_updated': 1580867088495,
               'last_updated_administrator': 100,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9033'},
              {'action': 'block',
               'description': 'demo_4',
               'id': 69,
               'last_updated': 1580867188053,
               'last_updated_administrator': 100,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9044'},
              {'action': 'block',
               'description': 'demo_5',
               'id': 70,
               'last_updated': 1580867476445,
               'last_updated_administrator': 100,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9055'},
              {'action': 'block',
               'description': 'demo_6',
               'id': 71,
               'last_updated': 1580867996552,
               'last_updated_administrator': 100,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9066'},
              {'action': 'block',
               'description': 'demo_7',
               'id': 72,
               'last_updated': 1580868101929,
               'last_updated_administrator': 100,
               'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9077'}]}

        """

        global_rules_api = api.GlobalRulesApi(self.api_client)
        rules_list = api.ApplicationControlGlobalRules()
        rules_list.application_control_global_rules = rules_array

        try:
            global_rules_api.add_global_rules(rules_list, self.api_version)
            api_response = global_rules_api.list_global_rules(self.api_version)

            print('\nUpdated Deep Security global rule list:')
            pprint(api_response)

            return api_response

        except ApiException as e:
            self._format_exception(e)

    @staticmethod
    def _format_exception(e):
        """Convenience method for extracting & returning error messages"""

        msg = json.loads(e.body)['message']
        print(f'\nError: {msg}')
        sys.exit(1)

    @staticmethod
    def read_rules_file(filename) -> list:
        """Reads CSV file into a list of lists

        Example:

        [['demo_1', '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9011'],
        ['demo_2', '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9022'],
        ['demo_3', '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9033']]

        :param filename: Filename to read
        :return: list
        """

        rules = []
        print(f'\nReading rules from {filename}...')

        with open(filename, 'r') as f:
            csv_rules = f.readlines()

        for entry in csv_rules:
            stripped_entry = entry.strip()
            split_entry = stripped_entry.split(',')
            split_entry[1] = split_entry[1].upper()

            rules.append(split_entry)

        print('Found the following rules:')
        pprint(rules)

        return rules


def main():

    ac = AppControlRuleSets()
    existing_rules = ac.get_global_rules()
    existing_rule_hashes = ac.get_existing_rule_hashes(existing_rules)
    new_rules = ac.read_rules_file(RULES_FILENAME)
    unique_rules = ac.get_unique_rules(existing_rule_hashes, new_rules)

    if unique_rules:
        global_rule_objects = ac.create_global_rule_objects(unique_rules)
        ac.create_global_rules(global_rule_objects)


if __name__ == '__main__':
    main()
