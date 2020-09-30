package main

var configbyte = []byte(`
{
    "title": "Leakin",
    "checks": [
        {
            "title": "AWS Client ID",
            "regex": "(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
            "severity": 6
        },
        {
            "title": "AWS Secret Key",
            "regex": "aws(.{0,20})?['\\\"][0-9a-z\\/+]{40}['\\\"]",
            "severity": 7
        },
        {
            "title": "AWS MWS key",
            "regex": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "severity": 8
        },
        {
            "title": "AWS ARN",
            "regex": "arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:.+",
            "severity": 1
        },
        {
            "title": "AWS EC2 Internal",
            "regex": "[0-9a-z.\\-_]+\\.compute(-1)?\\.internal",
            "severity": 1
        },
        {
            "title": "AWS EC2 External",
            "regex": "ec2-[0-9a-z.\\-_]+\\.compute(-1)?\\.amazonaws\\.com",
            "severity": 1
        },
        {
            "title": "AWS ELB",
            "regex": "[0-9a-z.\\-_]+\\.elb\\.amazonaws\\.com",
            "severity": 1
        },
        {
            "title": "AWS ELB",
            "regex": "[0-9a-z.\\-_]+\\.elb\\.[0-9a-z.\\-_]+\\.amazonaws\\.com",
            "severity": 1
        },
        {
            "title": "AWS RDS",
            "regex": "[0-9a-z.\\-_]+\\.rds\\.amazonaws\\.com",
            "severity": 1
        },
        {
            "title": "AWS ElasticCache",
            "regex": "[0-9a-z.\\-_]+\\.cache\\.amazonaws\\.com",
            "severity": 1
        },
        {
            "title": "AWS S3 Endpoint",
            "regex": "[0-9a-z.\\-_]+\\.s3\\.amazonaws\\.com",
            "severity": 1
        },
        {
            "title": "AWS S3 Endpoint",
            "regex": "[0-9a-z.\\-_]+\\.s3-website[0-9a-z.\\-_]+\\.amazonaws\\.com",
            "severity": 1
        },
        {
            "title": "AWS S3 Bucket",
            "regex": "s3://[0-9a-z.\\-_/]+",
            "severity": 1
        },
        {
            "title": "AWS CloudFront",
            "regex": "[0-9a-z.\\-_]+\\.cloudfront\\.net",
            "severity": 1
        },
        {
            "title": "AWS API Gateway",
            "regex": "[0-9a-z]+\\.execute-api\\.[0-9a-z.\\-_]+\\.amazonaws\\.com",
            "severity": 1
        },
        {
            "title": "Braintree API Key",
            "regex": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
            "severity": 9
        },
        {
            "title": "RKCS8",
            "regex": "-----BEGIN PRIVATE KEY-----",
            "severity": 10
        },
        {
            "title": "RSA",
            "regex": "-----BEGIN RSA PRIVATE KEY-----",
            "severity": 10
        },
        {
            "title": "SSH",
            "regex": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "severity": 10
        },
        {
            "title": "PGP",
            "regex": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "severity": 10
        },
        {
            "title": "Facebook Client ID",
            "regex": "(facebook|fb)(.{0,20})?['\\\"][0-9]{13,17}['\\\"]",
            "severity": 1
        },
        {
            "title": "Facebook Access Token",
            "regex": "EAACEdEose0cBA[0-9a-z]+",
            "severity": 6
        },
        {
            "title": "Facebook Secret Key",
            "regex": "(facebook|fb)(.{0,20})?['\\\"][0-9a-f]{32}['\\\"]",
            "severity": 7
        },
        {
            "title": "Generic Key",
            "regex": "[0-9a-z_]*(key)\\\\*['\"]?\\s*(:|=|=>|:=|\\|\\||;s:\\d+:)\\s*\\\\*['\"]([0-9]+[a-z]+[0-9a-z\\.\\-_=]{4,}|[a-z]+[0-9]+[0-9a-z\\.\\-_]{4,})",
            "severity": 1
        },
        {
            "title": "Generic Key",
            "regex": "[0-9a-z_]*(KEY)\\s*=\\s*['\"]?([0-9]+[a-z]+[0-9a-z\\.\\-_=]{4,}|[a-z]+[0-9]+[0-9a-z\\.\\-_]{4,})",
            "severity": 1
        },
        {
            "title": "Generic Token",
            "regex": "[0-9a-z_]*(token)\\\\*['\"]?\\s*(:|=|=>|:=|\\|\\||;s:\\d+:)\\s*\\\\*['\"]([0-9]+[a-z]+[0-9a-z\\.\\-_=]{4,}|[a-z]+[0-9]+[0-9a-z\\.\\-_]{6,})",
            "severity": 1
        },
        {
            "title": "Generic Token",
            "regex": "[0-9a-z_]*(TOKEN)\\s*=\\s*['\"]?([0-9]+[a-z]+[0-9a-z\\.\\-_=]{4,}|[a-z]+[0-9]+[0-9a-z\\.\\-_]{6,})",
            "severity": 1
        },
        {
            "title": "Generic Secret",
            "regex": "[0-9a-z_]*(secret)\\\\*['\"]\\s*(:|=|=>|:=|\\|\\||;s:\\d+:)\\s*\\\\*['\"][^\\s'\"]{6,}['\"]?",
            "severity": 1
        },
        {
            "title": "Generic Secret",
            "regex": "[0-9a-z_]*(SECRET)\\s*=\\s*['\"]?[^\\s'\"]{6,}['\"]?",
            "severity": 1
        },
        {
            "title": "Generic Password",
            "regex": "[0-9a-z_]*(password|passwd|pwd)\\\\*['\"]\\s*(:|=|=>|:=|\\|\\||;s:\\d+:)\\s*\\\\*['\"][^\\s'\"]{6,}['\"]?",
            "severity": 1
        },
        {
            "title": "Generic Password",
            "regex": "[0-9a-z_]*(PASSWORD|PASSWD|PWD)\\s*=\\s*['\"]?[^\\s'\"]{6,}['\"]?",
            "severity": 1
        },
        {
            "title": "Generic Authorization",
            "regex": "(authorization)\\s*:\\s*(bearer|token|basic)\\s+[0-9a-z\\.\\-_]{6,}",
            "severity": 1
        },
        {
            "title": "Sensitive URL Credentials",
            "regex": "(https?|ftp):\\/\\/[^\\s\\{\\}\\(\\)\\<\\>\\/%$'\"]+?:[^\\s\\{\\}\\(\\)\\<\\>\\/%]+?@[^\\s'\"\\)]+",
            "severity": 7
        },
        {
            "title": "Sensitive URL",
            "regex": "(https?|ftp):\\/\\/[^\\s\\{\\}\\(\\)\\<\\>\\/%$'\"]+?@[^\\s'\"\\)]+",
            "severity": 5
        },
        {
            "title": "GitHub Token",
            "regex": "github(.{0,20})?['\\\"][0-9a-z]{35,40}['\\\"]",
            "severity": 9
        },
        {
            "title": "Google Cloud Platform API key",
            "regex": "(google|gcp|youtube|drive|yt)(.{0,20})?['\\\"][AIza[0-9a-z\\\\-_]{35}]['\\\"]",
            "severity": 9
        },
        {
            "title": "Google API Key",
            "regex": "AIza[0-9a-z\\-_]{35}",
            "severity": 7
        },
        {
            "title": "Google Oauth ID",
            "regex": "[0-9]+-[0-9a-z_]{32}\\.apps\\.googleusercontent\\.com",
            "severity": 5
        },
        {
            "title": "Heroku API Key",
            "regex": "heroku(.{0,20})?['\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['\"]",
            "severity": 9
        },
        {
            "title": "LinkedIn Client ID",
            "regex": "linkedin(.{0,20})?['\\\"][0-9a-z]{12}['\\\"]",
            "severity": 6
        },
        {
            "title": "LinkedIn Secret Key",
            "regex": "linkedin(.{0,20})?['\\\"][0-9a-z]{16}['\\\"]",
            "severity": 7
        },
        {
            "title": "Mailchimp API Key",
            "regex": "[0-9a-f]{32}-us[0-9]{1,2}",
            "severity": 9
        },
        {
            "title": "Mailgun API Key",
            "regex": "key-[0-9a-z]{32}",
            "severity": 9
        },
        {
            "title": "Slack Token",
            "regex": "xox[baprs]-([0-9a-z-]{10,48})",
            "severity": 9
        },
        {
            "title": "Square API Key",
            "regex": "sq0(atp|csp)-[0-9a-z\\-_]{22,43}",
            "severity": 9
        },
        {
            "title": "Stripe Secret Live Key",
            "regex": "(sk|rk)_live_[0-9a-z]{24}",
            "severity": 10
        },
        {
            "title": "Stripe Secret Test Key",
            "regex": "(sk|rk)_test_[0-9a-z]{24}",
            "severity": 5
        },
        {
            "title": "Stripe Public Live Key",
            "regex": "pk_live_[0-9a-z]{24}",
            "severity": 1
        },
        {
            "title": "Stripe Public Test Key",
            "regex": "pk_test_[0-9a-z]{24}",
            "severity": 1
        },
        {
            "title": "Telegram Secret",
            "regex": "\\d{5,}:A[0-9a-z_\\-]{34,34}",
            "severity": 7
        },
        {
            "title": "Trello URL",
            "regex": "https://trello.com/b/[0-9a-z]/[0-9a-z_-]+",
            "severity": 1
        },
        {
            "title": "Twilio API Key",
            "regex": "SK[0-9a-fA-F]{32}",
            "severity": 8
        },
        {
            "title": "Twitter Client ID",
            "regex": "twitter(.{0,20})?['\\\"][0-9a-z]{18,25}['\\\"]",
            "severity": 6
        },
        {
            "title": "Twitter Secret Key",
            "regex": "twitter(.{0,20})?['\\\"][0-9a-z]{35,44}['\\\"]",
            "severity": 7
        }
    ]
}
`)
