# Deep Security Application Protection global rules

Turns CSV entries into [Deep Security global rules](https://help.deepsecurity.trendmicro.com/12_0/on-premise/Protection-Modules/Application-Control/rulesets-via-relays.html).

## Usage

1. Modify the `rules.csv` file to suit your needs.
2. Run the script: ```python3 run.py```

### Example Output

```
Reading existing rules from Deep Security...
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
 'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9055'}]

Extracting hashes from existing rules...
Found the following hashes:
['7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9069',
 '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9068',
 '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9022',
 '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9023',
 '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9011',
 '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9033',
 '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9044',
 '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9055']

Reading rules from rules.csv...
Found the following rules:
[['demo_1', '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9011'],
 ['demo_2', '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9022'],
 ['demo_3', '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9033'],
 ['demo_4', '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9044'],
 ['demo_5', '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9055'],
 ['demo_6', '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9066']]

Comparing new rules to existing rules...
Found existing hash: 7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9011
Found existing hash: 7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9022
Found existing hash: 7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9033
Found existing hash: 7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9044
Found existing hash: 7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9055
Found new hash (demo_6): 7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9066

All new hashes which were found:
[['demo_6', '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9066']]

Updated Deep Security global rule list:
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
                                       'sha256': '7F83B1657FF1FC53B92DC18148A1D65DFC2D4B1FA3D677284ADDD200126D9066'}]}

Process finished with exit code 0
```