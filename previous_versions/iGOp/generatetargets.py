# 10.x.1.4
# 10.x.1.5

import json
import os

def main():
    teams = input("Enter number of teams or \"wipe\" to delete current: ")
    if teams == "wipe":
        os.system("rm targets.json")
    if not teams.isdigit():
        print("Bruh")
    else:
        with open ("targets.txt", "w") as f:
            for x in range(1,int(teams)+1):
                f.write(f"10.{x}.1.10\n")
                f.write(f"10.{x}.1.40\n")
                f.write(f"10.{x}.2.2\n")
                f.write(f"10.{x}.2.3\n")
                f.write(f"10.{x}.2.4\n")        

        # json_object = json.dumps(targets, indent=4)

        # with open("targets.json", "w") as outfile:
        #     outfile.write(json_object)
    


if __name__ == "__main__":
    main()