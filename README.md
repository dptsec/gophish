![gophish logo](https://raw.github.com/gophish/gophish/master/static/images/gophish_purple.png)

Gophish
=======

![Build Status](https://github.com/dptsec/gophish/workflows/CI/badge.svg) [![GoDoc](https://godoc.org/github.com/dptsec/gophish?status.svg)](https://godoc.org/github.com/dptsec/gophish)

Gophish: Open-Source Phishing Toolkit

> **Note:** This is an enhanced fork of the original [Gophish project](https://github.com/gophish/gophish) with additional security and evasion features for professional penetration testing engagements.

[Gophish](https://getgophish.com) is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.

### Enhanced Features

This fork includes the following additional capabilities:

#### IP Blacklist Filtering
- **Flexible IP Filtering**: Support for single IPs, IP ranges (hyphenated), comma-separated lists, and CIDR blocks
- **Configurable Actions**: Per-entry actions including "ignore" (log and continue), "notfound" (404 response), or "redirect" (302 redirect)
- **Configuration-based**: Manage blacklists via `config.json` without database changes
- **Use Cases**: Filter internal testing IPs, block security scanners, or redirect unwanted traffic

Example configuration:
```json
{
  "phish_server": {
    "ip_blacklist": [
      {"ip_range": "192.168.1.0/24", "action": "notfound"},
      {"ip_range": "10.0.0.1-10.0.0.50", "action": "ignore"},
      {"ip_range": "1.1.1.1,2.2.2.2", "action": "redirect", "redirect_url": "https://example.com"}
    ]
  }
}
```

#### Detection Evasion
- **Header Sanitization**: Configurable removal or customization of identifying HTTP headers (X-Mailer, X-Gophish-Contact, X-Server)
- **URL Parameter Obfuscation**: Customizable recipient ID parameter (default changed from "rid" to "id")
- **Tracking Pixel Randomization**: Dynamically generated tracking pixels with random RGB values to prevent static fingerprinting
- **Server Identity Masking**: Configurable server name (defaults to "nginx" instead of "gophish")

Example configuration:
```json
{
  "phish_server": {
    "server_name": "nginx",
    "x_mailer": "Mozilla/5.0",
    "recipient_parameter": "id",
    "enable_contact_header": false,
    "enable_server_header": false
  }
}
```

### Install

Installation of Gophish is dead-simple - just download and extract the zip containing the [release for your system](https://github.com/dptsec/gophish/releases/), and run the binary. Gophish has binary releases for Windows, Mac, and Linux platforms.

### Building From Source
**If you are building from source, please note that Gophish requires Go v1.10 or above!**

To build Gophish from source, simply run ```git clone https://github.com/dptsec/gophish.git``` and ```cd``` into the project source directory. Then, run ```go build```. After this, you should have a binary called ```gophish``` in the current directory.

### Docker
You can also use Gophish via the official Docker container [here](https://hub.docker.com/r/gophish/gophish/).

### Setup
After running the Gophish binary, open an Internet browser to https://localhost:3333 and login with the default username and password listed in the log output.
e.g.
```
time="2020-07-29T01:24:08Z" level=info msg="Please login with the username admin and the password 4304d5255378177d"
```

Releases of Gophish prior to v0.10.1 have a default username of `admin` and password of `gophish`.

### Documentation

Documentation can be found on our [site](http://getgophish.com/documentation). Find something missing? Let us know by filing an issue!

### Issues

Find a bug? Want more features? Find something missing in the documentation? Let us know! Please don't hesitate to [file an issue](https://github.com/dptsec/gophish/issues/new) and we'll get right on it.

### License
```
Gophish - Open-Source Phishing Framework

The MIT License (MIT)

Copyright (c) 2013 - 2020 Jordan Wright

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software ("Gophish Community Edition") and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```
