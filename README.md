# SYMFONY SOCIAL LOGIN
This project is made with Symfony 5.2 and PHP 7.4.

### Running the app
After cloning or downloading the repo, navigate to the project directory and follow the steps mentioned below.
1. Install the backend dependencies: `composer install`.
2. Update database configuration, edit this line in `.env` file with your own configuration
   `DATABASE_URL=mysql://db_user:db_password@127.0.0.1:3306/db_name`
3. Create database & tables with `php bin/console d:d:c` and `php bin/console d:s:u --force`
4. Start the server with Symfony: `symfony serve`

### Configuration
Notice the two `'%env(var)%'`calls? Add these anywhere in your `.env` file.
These are the credentials for the OAuth provider. For Facebook, you'll get these by registering
your app on [developers.facebook.com](https://developers.facebook.com/apps/), for GitHub, you'll get these by registering
your app on [Developer settings](https://github.com/settings/developers) and for Google, on [console.developers.google](https://console.developers.google.com/apis/credentials).

```bash
# .env
# ...

OAUTH_GITHUB_ID=github_id
OAUTH_GITHUB_SECRET=github_secret

OAUTH_FACEBOOK_ID=facebook_id
OAUTH_FACEBOOK_SECRET=facebook_secret

OAUTH_GOOGLE_CLIENT_ID=google_client_id
OAUTH_GOOGLE_CLIENT_SECRET=google_client_secret
```

#### Callback URL
- For Facebook `{BASE_URL}/oauth/check/facebook`
- For GitHub `{BASE_URL}/oauth/check/github`
- For Google `{BASE_URL}/oauth/check/google`

### DOCS
[OAuth / Social Integration for Symfony: KnpUOAuth2ClientBundle](https://github.com/knpuniversity/oauth2-client-bundle)