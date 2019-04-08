# Phishing catcher (on steroids?)

Catching malicious phishing domain names using [certstream](https://certstream.calidog.io/) SSL certificates live stream.

Blacklist generation to feed a [Pi-hole](https://github.com/pi-hole/pi-hole/blob/master/README.md)

**Wildcard domains exclusion**

Notification of a new domain added via [Telegram bot](https://core.telegram.org/bots) 

..and (optional) extended logging to file (very verbose, make sure to write it in ramdisk and rotate it frequently)

![logging](https://i.imgur.com/c8JsfCM.png)

also, it will show your bot token in the logs.. *Thanks urllib3* ..ugh..

This is just a working PoC, feel free to contribute and tweak the code to fit your needs 👍

![usage](https://i.imgur.com/4BGuXkR.gif)


### Requirements

- GNU/Linux (tested on Raspbian 9)
- Python version > 3.6
- pip3 (to install the requirements)
- venv (optional)
- gcc and python-dev package (to compile the pip packages required)

### Installation
- Use venv if possible (optional)
```sh
$ python -m virtualenv env
$ source env/bin/activate
```

- You will need the python packages as specified in the requirements.txt file

```sh
$ pip3 install -r requirements.txt
```

### Usage

first, edit the config.yml by providing the following information:
- Telegram bot [TOKEN](https://telepot.readthedocs.io/en/latest/#id5) 
- Telegram [id](https://telepot.readthedocs.io/en/latest/#id7) 
- Server IP address (127.0.0.1 if you want to run it only locally)
- TCP port where the blacklist will be server (any port > 1024 will do, unless you want to run the script as root, and you don't, don't you??)
- Blacklist filename (any name will do, as long as you keep the .txt extension in order for Pihole to like it)
- Logs filename
- Score beyond which phishing_catcher will save new phishing domains (tradeoff between too many false positives and skipping potentially interesting domains.. With the default keywords, I suggest a value of 135)

and then, you're ready to roll:

```
$ python3 catch_phishing.py
```

### Example phishing notification
![Bot notification](https://i.imgur.com/24FNAI8.png)

### Example phishing caught

![Paypal Phishing](https://i.imgur.com/AK60EYz.png)

License
----
GNU GPLv3

If this tool has been useful for you, feel free to thank [x0rz](https://github.com/x0rz) by buying him a coffee

[![Coffee](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoff.ee/x0rz)
