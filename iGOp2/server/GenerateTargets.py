import os

def main():
    addresses = []
    print("This version contains no error checking, check targets.txt is correct before loading clients.")
    while True:
        config = input("Enter configuration in format: 1.1.x.1, use \"x\" for team variable, or \"done\" to continue: ")
        if config.lower() == "done":
            break
        addresses.append(config)

    teams = input("Enter number of teams or \"wipe\" to delete current: ")
    if teams == "wipe":
        os.system("rm targets.json")
    if not teams.isdigit():
        print("Bruh")
    else:
        with open ("targets.txt", "w") as f:
            for x in range(1,int(teams)+1):
                for address in addresses:
                    tokens = address.split('x')
                    if len(tokens) == 1:
                        target = tokens[0] + str(x)
                    else:  
                        target = tokens[0] + str(x) + tokens[1] + "\n"
                    f.write(target)

if __name__ == "__main__":
    main()