# 10.x.1.4
# 10.x.1.5

import json
import os

def main():
    targets = dict()
    teams = input("Enter number of teams or \"wipe\" to delete current: ")
    if teams == "wipe":
        os.system("rm targets.json")
    if not teams.isdigit():
        print("Bruh")
    else:
        for x in range(1,int(teams)+1):
            targets[f"Team{x}Box4"] = f"10.{x}.1.4" 
            targets[f"Team{x}Box5"] = f"10.{x}.1.5"

        json_object = json.dumps(targets, indent=4)

        with open("targets.json", "w") as outfile:
            outfile.write(json_object)
    


if __name__ == "__main__":
    main()