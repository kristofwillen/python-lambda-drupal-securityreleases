# python-lambda-drupal-securityreleases

This reposiotory contains a SAM Cloudformation template for a lambda function which will alert you if a new Drupal security release has been published. I wrote this function as my Drupal site is harbored in an AWS LightSail VPS, which has no mail functionality. 

## Usage
* change the DRUPAL_MAJOR_RELEASE to the major release of your Drupal server
* Deploy with :
```bash
$ sam build
$ sam deploy
```

## Infrastructure
<img src=doc/infra.png>
