# Update a file


## Add lines to /etc/hosts

```bash
echo "10.10.11.170 site.com" | sudo tee -a /etc/hosts
```

## Remove last line from /etc/hosts
```bash
sudo sed -i '$d' /etc/hosts

```


