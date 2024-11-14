# Authorize

![Build Status](https://github.com/simplesamlphp/simplesamlphp-module-authorize/actions/workflows/php.yml/badge.svg)
[![Coverage Status](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-authorize/branch/master/graph/badge.svg)](https://codecov.io/gh/simplesamlphp/simplesamlphp-module-authorize)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-authorize/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/simplesamlphp/simplesamlphp-module-authorize/?branch=master)
[![Type Coverage](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-authorize/coverage.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-authorize)
[![Psalm Level](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-authorize/level.svg)](https://shepherd.dev/github/simplesamlphp/simplesamlphp-module-authorize)

## Install

Install with composer

```json
    "repositories": [
        {
            "type": "package",
            "package": {
                "name": "hhs/simplesamlphp-module-uwpoash",
                "type": "simplesamlphp-module",
                "version": "1.0",
                "source": {
                    "url": "https://github.com/hhs/simplesamlphp-module-uwpoash.git",
                    "type": "git",
                    "reference": "master"
                }
            }
        }
    ],
```

```bash
    composer require hhs/simplesamlphp-module-uwpoash
```

## Configuration

Next thing you need to do is to enable the module: in `config.php`,
search for the `module.enable` key and set `uwpoash` to true:

```php
    'module.enable' => [
        'uwpoash' => true,
        …
    ],
    …
    'authproc.sp' => [
        …
        60 => [
        'class' => 'uwpoash:Authorize',
        'deny'  => true,
        'IAL' => [
            'value' => '3',
            'operator' => '<',
        ],
        'AAL' => [
            'value' => '3',
            'operator' => '<',
            'exception' => 'PIVException',
        ],
        'errorURL' => true,
        'appName' => 'AMS-APP-LOA4',
        'loginURL' => sprintf('https://%s.odphp.health.gov/saml_login', $_ENV['DEPLOYMENT_GROUP_NAME']),
        'show_user_attribute' => 'EmailAddress',
        ],
        …
    ],
```
To use the OASH theme, you may also use this module as a theme:

```php
    'theme.use' => 'uwpoash:uwp',
```
