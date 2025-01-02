Smartbomber's Little Helper

Monitors ~/Documents/EVE/logs/Gamelogs for updates and watches for lines where damage is applied to dreadnoughts or titans. When a dread spawns while smartbomb ratting, you will naturally produce logs that you are applying damage. When this is detected, the application sends an alert to the user.

I wrote this in python and used pyinstaller to pack it into a single exe. For this reason, the exe ends up being rather large for being such a small script. Python isn't the best language for this type of thing but it is what it is.