# GameVault DBMS - Naurose

## Instructions
### Have XAMPP and Node.js along with Node Package Manager npm installed in order to operate the server.
1. Start `Apache` and `MySQl` in XAMPP.
2. Go to phpmyadmin, click on the `Admin` button next to the `MySQl` start button, import the SQL file named schema.sql.
3. Go to RAWG API's website, sign in and acquire a free API key.
4. In vscode, open the folder and go to the .env file where the API key needs to be added.
5. Run the scripts to populate the database. A users script can be run to have premade users to easily login.

#### Commands:
```
npm run seed-users
npm run seed-games
npm start
```


Owner: https://github.com/Naurose
