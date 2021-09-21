import os, json, re
import sys
sys.path.append("/home/syuu/Project/apk_process")
from pprint import pprint
from collections import Counter

def analysis_architecture():
    """[summary]

    Args:
        file ([type]): [description]
    """
    with open("files/Total_data.json", "r") as f:
        data = json.load(f)
    architectures = []
    for file in data:
        if len(data[file]) > 0:
            for h in data[file]:
                architectures.append(data[file][h]["architecture"])
    architecture_statistics = dict(Counter(architectures))
    with open("statistics_files/architecture_statistics.json", "w") as f:
        json.dump(architecture_statistics, f)
    print(architecture_statistics)
    
            

if __name__ == '__main__':
    analysis_architecture()
