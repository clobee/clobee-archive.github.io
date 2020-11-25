# Package Development

When developping PHP packages locally I often use a symbolic link
`ln -s /vagrant/my-package/ /vagrant/www.my-site.com/vendor/my-package`

This technique doesn't allow the use of composer commands (E.g composer install)

## composer `symlink`

```
#composer.json

  "repositories": {
    "dev-package": {
      "type": "path",
      "url": "/vagrant/my-bundle",
      "options": {
        "symlink": true
      }
    },
  },
  "minimum-stability": "dev",
  "prefer-stable": true,
...
"my/package/name": "dev-master",
...
```

## Use a custom private repo?

```
  "repositories": [
    {
        "type": "package",
        "package": {
            "name": "my-project/my-package",
            "version": "0.0.1",
            "type": "package",
            "source": {
                "url": "git@github.com:/my-project/my-package.git",
                "type": "git",
                "reference": "master"
            }
        }
    }
  ],
```

## Troubleshooting

If the package has been downloaded previously, remove it `rm -rf vendor/package` then just run `composer require {PACKAGE}` and we should be ready for a beer :)

```
rm -rf vendor/my-project/my-package/
rm composer.lock
composer clearcache
rm -rf ~/.cache/composer/
```
