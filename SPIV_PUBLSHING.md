```
`ssh graham.sanderson@asic-gateway`
cd /home/amethyst/work/graham/amethyst
source project_setup.sh
spiv pull

cd ip/snps_otp
git checkout master
git pull
cd wrapper/contents_vrb
edit otp_data.vrb
vrbuild otp_data.vrb
git add -A .
git commit -a -m "Add blah to otp data"
git push
```

To publish to amethystcd $PROJ_ROOT

```
spiv publish-ip snps_otp
git commit spiv/dependencies -m "Add blah to otp data"
git push
```

To publish amy-bootrom:

Go to amethyst checkout
Do a spiv pull
Go into software/amy-bootrom
Checkout a2-dev branch
Do a git pull
Do a spiv publish-ip --yes amy-bootrom
Cd back to project level, and commit change to spiv/dependencies