# PHP-AUTO-REST-API-MAKER

Single file PHP 7 script that adds a REST API to a MySQL 5.6 InnoDB database. PostgreSQL 9.1 and MS SQL Server 2012 are fully supported. 
## Requirements

  - PHP 7.0 or higher with PDO drivers for MySQL, PgSQL or SqlSrv enabled
  - MySQL 5.6 / MariaDB 10.0 or higher for spatial features in MySQL
  - PostGIS 2.0 or higher for spatial features in PostgreSQL 9.1 or higher
  - SQL Server 2012 or higher (2017 for Linux support)

## Installation

This is a single file application! Upload "`api.php`" somewhere and enjoy!

For local development you may run PHP's built-in web server:

    php -S localhost:8080

Test the script by opening the following URL:

    http://localhost:8080/api.php/records/posts/1

Don't forget to modify the configuration at the bottom of the file.

## Configuration

Edit the following lines in the bottom of the file "`api.php`":

    $config = new Config([
        'username' => 'xxx',
        'password' => 'xxx',
        'database' => 'xxx',
    ]);


## Features

The following features are supported:

  - Composer install or single PHP file, easy to deploy.
  - Very little code, easy to adapt and maintain
  - Supports POST variables as input (x-www-form-urlencoded)
  - Supports a JSON object as input
  - Supports a JSON array as input (batch insert)
  - Sanitize and validate input using callbacks
  - Permission system for databases, tables, columns and records
  - Multi-tenant single and multi database layouts are supported
  - Multi-domain CORS support for cross-domain requests
  - Support for reading joined results from multiple tables
  - Search support on multiple criteria
  - Pagination, sorting, top N list and column selection
  - Relation detection with nested results (belongsTo, hasMany and HABTM)
  - Atomic increment support via PATCH (for counters)
  - Binary fields supported with base64 encoding
  - Spatial/GIS fields and filters supported with WKT and GeoJSON
  - Generate API documentation using OpenAPI tools
  - Authentication via JWT token or username/password
  - Database connection parameters may depend on authentication
  - Support for reading database structure in JSON
  - Support for modifying database structure using REST endpoint
  - Security enhancing middleware is included





### CRUD + List

The example posts table has only a a few fields:

    posts  
    =======
    id     
    title  
    content
    created

The CRUD + List operations below act on this table.

#### Create

If you want to create a record the request can be written in URL format as: 

    POST /records/posts

You have to send a body containing:

    {
        "title": "Black is the new red",
        "content": "This is the second post.",
        "created": "2018-03-06T21:34:01Z"
    }

And it will return the value of the primary key of the newly created record:

    2

#### Read

To read a record from this table the request can be written in URL format as:

    GET /records/posts/1

Where "1" is the value of the primary key of the record that you want to read. It will return:

    {
        "id": 1
        "title": "Hello world!",
        "content": "Welcome to the first post.",
        "created": "2018-03-05T20:12:56Z"
    }

On read operations you may apply joins.

#### Update

To update a record in this table the request can be written in URL format as:

    PUT /records/posts/1

Where "1" is the value of the primary key of the record that you want to update. Send as a body:

    {
        "title": "Adjusted title!"
    }

This adjusts the title of the post. And the return value is the number of rows that are set:

    1

#### Delete

If you want to delete a record from this table the request can be written in URL format as:

    DELETE /records/posts/1

And it will return the number of deleted rows:

    1

#### List

To list records from this table the request can be written in URL format as:

    GET /records/posts

It will return:

    {
        "records":[
            {
                "id": 1,
                "title": "Hello world!",
                "content": "Welcome to the first post.",
                "created": "2018-03-05T20:12:56Z"
            }
        ]
    }

On list operations you may apply filters and joins.

### Filters

Filters provide search functionality, on list calls, using the "filter" parameter. You need to specify the column
name, a comma, the match type, another commma and the value you want to filter on. These are supported match types:

  - "cs": contain string (string contains value)
  - "sw": start with (string starts with value)
  - "ew": end with (string end with value)
  - "eq": equal (string or number matches exactly)
  - "lt": lower than (number is lower than value)
  - "le": lower or equal (number is lower than or equal to value)
  - "ge": greater or equal (number is higher than or equal to value)
  - "gt": greater than (number is higher than value)
  - "bt": between (number is between two comma separated values)
  - "in": in (number or string is in comma separated list of values)
  - "is": is null (field contains "NULL" value)

You can negate all filters by prepending a "n" character, so that "eq" becomes "neq". 
Examples of filter usage are:

    GET /records/categories?filter=name,eq,Internet
    GET /records/categories?filter=name,sw,Inter
    GET /records/categories?filter=id,le,1
    GET /records/categories?filter=id,ngt,2
    GET /records/categories?filter=id,bt,1,1

Output:

    {
        "records":[
            {
                "id": 1
                "name": "Internet"
            }
        ]
    }

In the next section we dive deeper into how you can apply multiple filters on a single list call.

### Multiple filters

Filters can be a by applied by repeating the "filter" parameter in the URL. For example the following URL: 

    GET /records/categories?filter=id,gt,1&filter=id,lt,3

will request all categories "where id > 1 and id < 3". If you wanted "where id = 2 or id = 4" you should write:

    GET /records/categories?filter1=id,eq,2&filter2=id,eq,4
    
As you see we added a number to the "filter" parameter to indicate that "OR" instead of "AND" should be applied.
Note that you can also repeat "filter1" and create an "AND" within an "OR". Since you can also go one level deeper
by adding a letter (a-f) you can create almost any reasonably complex condition tree.

NB: You can only filter on the requested table (not on it's included) and filters are only applied on list calls.

### Column selection

By default all columns are selected. With the "include" parameter you can select specific columns. 
You may use a dot to separate the table name from the column name. Multiple columns should be comma separated. 
An asterisk ("*") may be used as a wildcard to indicate "all columns". Similar to "include" you may use the "exclude" parameter to remove certain columns:

```
GET /records/categories/1?include=name
GET /records/categories/1?include=categories.name
GET /records/categories/1?exclude=categories.id
```

Output:

```
    {
        "name": "Internet"
    }
```

NB: Columns that are used to include related entities are automatically added and cannot be left out of the output.

### Ordering

With the "order" parameter you can sort. By default the sort is in ascending order, but by specifying "desc" this can be reversed:

```
GET /records/categories?order=name,desc
GET /records/categories?order=id,desc&order=name
```

Output:

```
    {
        "records":[
            {
                "id": 3
                "name": "Web development"
            },
            {
                "id": 1
                "name": "Internet"
            }
        ]
    }
```

NB: You may sort on multiple fields by using multiple "order" parameters. You can not order on "joined" columns.

### Limit size

The "size" parameter limits the number of returned records. This can be used for top N lists together with the "order" parameter (use descending order).

```
GET /records/categories?order=id,desc&size=1
```

Output:

```
    {
        "records":[
            {
                "id": 3
                "name": "Web development"
            }
        ]
    }
```

NB: If you also want to know to the total number of records you may want to use the "page" parameter.

### Pagination

The "page" parameter holds the requested page. The default page size is 20, but can be adjusted (e.g. to 50).

```
GET /records/categories?order=id&page=1
GET /records/categories?order=id&page=1,50
```

Output:

```
    {
        "records":[
            {
                "id": 1
                "name": "Internet"
            },
            {
                "id": 3
                "name": "Web development"
            }
        ],
        "results": 2
    }
```

NB: Since pages that are not ordered cannot be paginated, pages will be ordered by primary key.

### Joins

Let's say that you have a posts table that has comments (made by users) and the posts can have tags.

    posts    comments  users     post_tags  tags
    =======  ========  =======   =========  ======= 
    id       id        id        id         id
    title    post_id   username  post_id    name
    content  user_id   phone     tag_id
    created  message

When you want to list posts with their comments users and tags you can ask for two "tree" paths:

    posts -> comments  -> users
    posts -> post_tags -> tags

These paths have the same root and this request can be written in URL format as:

    GET /records/posts?join=comments,users&join=tags

Here you are allowed to leave out the intermediate table that binds posts to tags. In this example
you see all three table relation types (hasMany, belongsTo and hasAndBelongsToMany) in effect:

- "post" has many "comments"
- "comment" belongs to "user"
- "post" has and belongs to many "tags"

This may lead to the following JSON data:

    {
        "records":[
            {
                "id": 1,
                "title": "Hello world!",
                "content": "Welcome to the first post.",
                "created": "2018-03-05T20:12:56Z",
                "comments": [
                    {
                        id: 1,
                        post_id: 1,
                        user_id: {
                            id: 1,
                            username: "mevdschee",
                            phone: null,
                        },
                        message: "Hi!"
                    },
                    {
                        id: 2,
                        post_id: 1,
                        user_id: {
                            id: 1,
                            username: "mevdschee",
                            phone: null,
                        },
                        message: "Hi again!"
                    }
                ],
                "tags": []
            },
            {
                "id": 2,
                "title": "Black is the new red",
                "content": "This is the second post.",
                "created": "2018-03-06T21:34:01Z",
                "comments": [],
                "tags": [
                    {
                        id: 1,
                        message: "Funny"
                    },
                    {
                        id: 2,
                        message: "Informational"
                    }
                ]
            }
        ]
    }

You see that the "belongsTo" relationships are detected and the foreign key value is replaced by the referenced object.
In case of "hasMany" and "hasAndBelongsToMany" the table name is used a new property on the object.


### Authentication

Currently there are three types of authentication supported. They all store the authenticated user in the `$_SESSION` super global.
This variable can be used in the authorization handlers to decide wether or not sombeody should have read or write access to certain tables, columns or records.
The following overview shows the kinds of authentication middleware that you can enable.

| Name     | Middleware | Authenticated via      | Users are stored in | Session variable        |
| -------- | ---------- | ---------------------- | ------------------- | ----------------------- |
| Database | dbAuth     | '/login' endpoint      | database table      | `$_SESSION['user']`     |
| Basic    | basicAuth  | 'Authorization' header | '.htpasswd' file    | `$_SESSION['username']` |
| JWT      | jwtAuth    | 'Authorization' header | identity provider   | `$_SESSION['claims']`   |

Below you find more information on each of the authentication types.

#### Database authentication

The database authentication middleware defines two new routes:

    method path       - parameters               - description
    ----------------------------------------------------------------------------------------
    POST   /login     - username + password      - logs a user in by username and password
    POST   /logout    -                          - logs out the currently logged in user

A user can be logged in by sending it's username and password to the login endpoint (in JSON format).
The authenticated user (with all it's properties) will be stored in the `$_SESSION['user']` variable.
The user can be logged out by sending a POST request with an empty body to the logout endpoint.
The passwords are stored as hashes in the password column in the users table. To generate the hash value
for the password 'pass2' you can run on the command line:

    php -r 'echo password_hash("pass2", PASSWORD_DEFAULT)."\n";'

It is IMPORTANT to restrict access to the users table using the 'authorization' middleware, otherwise all 
users can freely add, modify or delete any account! The minimal configuration is shown below:

    'middlewares' => 'dbAuth,authorization',
    'authorization.tableHandler' => function ($operation, $tableName) {
        return $tableName != 'users';
    },

Note that this middleware uses session cookies and stores the logged in state on the server.

#### Basic authentication

The Basic type supports a file (by default '.htpasswd') that holds the users and their (hashed) passwords separated by a colon (':'). 
When the passwords are entered in plain text they fill be automatically hashed.
The authenticated username will be stored in the `$_SESSION['username']` variable.
You need to send an "Authorization" header containing a base64 url encoded and colon separated username and password after the word "Basic".

    Authorization: Basic dXNlcm5hbWUxOnBhc3N3b3JkMQ

This example sends the string "username1:password1".

#### JWT authentication

The JWT type requires another (SSO/Identity) server to sign a token that contains claims. 
Both servers share a secret so that they can either sign or verify that the signature is valid.
Claims are stored in the `$_SESSION['claims']` variable. You need to send an "X-Authorization" 
header containing a base64 url encoded and dot separated token header, body and signature after
the word "Bearer" ([read more about JWT here](https://jwt.io/)). The standard says you need to
use the "Authorization" header, but this is problematic in Apache and PHP.

    X-Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6IjE1MzgyMDc2MDUiLCJleHAiOjE1MzgyMDc2MzV9.Z5px_GT15TRKhJCTHhDt5Z6K6LRDSFnLj8U5ok9l7gw

This example sends the signed claims:

    {
      "sub": "1234567890",
      "name": "John Doe",
      "admin": true,
      "iat": "1538207605",
      "exp": 1538207635
    }

NB: The JWT implementation only supports the RSA and HMAC based algorithms.

##### Configure and test JWT authentication with Auth0

First you need to create an account on [Auth0](https://auth0.com/auth/login).
Once logged in, you have to create an application (its type does not matter). Collect the `Domain`
and `Client ID` and keep them for a later use. Then, create an API: give it a name and fill the
`identifier` field with your API endpoint's URL.

Then you have to configure the `jwtAuth.secrets` configuration in your `api.php` file.
Don't fill it with the `secret` you will find in your Auth0 application settings but with **a
public certificate**. To find it, go to the settings of your application, then in "Extra settings".
You will now find a "Certificates" tab where you will find your Public Key in the Signing
Certificate field.

To test your integration, you can copy the [auth0/vanilla.html](examples/clients/auth0/vanilla.html)
file. Be sure to fill these three variables:

 - `authUrl` with your Auth0 domain
 - `clientId` with your Client ID
 - `audience` with the API URL you created in Auth0

⚠️ If you don't fill the audience parameter, it will not work because you won't get a valid JWT.

You can also change the `url` variable, used to test the API with authentication.

[More info](https://auth0.com/docs/api-auth/tutorials/verify-access-token)

##### Configure and test JWT authentication with Firebase

First you need to create a Firebase project on the [Firebase console](https://console.firebase.google.com/).
Add a web application to this project and grab the code snippet for later use.

Then you have to configure the `jwtAuth.secrets` configuration in your `api.php` file. 
This can be done as follows:

a. Log a user in to your Firebase-based app, get an authentication token for that user
b. Go to [https://jwt.io/](https://jwt.io/) and paste the token in the decoding field
c. Read the decoded header information from the token, it will give you the correct `kid`
d. Grab the public key via this [URL](https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com), which corresponds to your `kid` from previous step
e. Now, just fill `jwtAuth.secrets` with your public key in the `api.php`

Here is an example of what it should look like in the configuration:

```
...,
'middlewares' => 'cors, jwtAuth, authorization',
        'jwtAuth.secrets' => "ce5ced6e40dcd1eff407048867b1ed1e706686a0:-----BEGIN CERTIFICATE-----\nMIIDHDCCAgSgAwIBAgIIExun9bJSK1wwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE\nAxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMTkx\nMjIyMjEyMTA3WhcNMjAwMTA4MDkzNjA3WjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl\nbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD\nggEPADCCAQoCggEBAKsvVDUwXeYQtySNvyI1/tZAk0sj7Zx4/1+YLUomwlK6vmEd\nyl2IXOYOj3VR7FBA24A9//nnrp+mV8YOYEOdaWX7PQo0PIPFPqdA0r7CqBUWHPfQ\n1WVHVRQY3G0c7upM97UfMes9xOrMqyvecMRk1e5S6eT12Zh2og7yiVs8gP83M1EB\nGqseUaltaadjyT35w5B0Ny0/7NdLYiv2G6Z0S821SxvSo1/wfmilnBBKYYluP0PA\n9NPznWFP6uXnX7gKxyJT9//cYVxTO6+b1TT13Yvrpm1a4EuCOhLrZH6ErHQTccAM\nhAx8mdNtbROsp0dlPKrSfqO82uFz45RXZYmSeP0CAwEAAaM4MDYwDAYDVR0TAQH/\nBAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ\nKoZIhvcNAQEFBQADggEBACNsJ5m00gdTvD6j6ahURsGrNZ0VJ0YREVQ5U2Jtubr8\nn2fuhMxkB8147ISzfi6wZR+yNwPGjlr8JkAHAC0i+Nam9SqRyfZLqsm+tHdgFT8h\npa+R/FoGrrLzxJNRiv0Trip8hZjgz3PClz6KxBQzqL+rfGV2MbwTXuBoEvLU1mYA\no3/UboJT7cNGjZ8nHXeoKMsec1/H55lUdconbTm5iMU1sTDf+3StGYzTwC+H6yc2\nY3zIq3/cQUCrETkALrqzyCnLjRrLYZu36ITOaKUbtmZhwrP99i2f+H4Ab2i8jeMu\nk61HD29mROYjl95Mko2BxL+76To7+pmn73U9auT+xfA=\n-----END CERTIFICATE-----\n",
        'cors.allowedOrigins' => '*',
        'cors.allowHeaders' => 'X-Authorization'
```

Notes:
 - The `kid:key` pair is formatted as a string
 - Do not include spaces before or after the ':'
 - Use double quotation marks (") around the string text
 - The string must contain the linefeeds (\n)

To test your integration, you can copy the [firebase/vanilla.html](examples/clients/firebase/vanilla.html)
file and the [firebase/vanilla-success.html](examples/clients/firebase/vanilla-success.html) file,
used as a "success" page and to display the API result.

Replace, in both files, the Firebase configuration (`firebaseConfig` object).

You can also change the `url` variable, used to test the API with authentication.

[More info](https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library)

### Authorizing operations

The Authorization model acts on "operations". The most important ones are listed here:

    method path                  - operation - description
    ----------------------------------------------------------------------------------------
    GET    /records/{table}      - list      - lists records
    POST   /records/{table}      - create    - creates records
    GET    /records/{table}/{id} - read      - reads a record by primary key
    PUT    /records/{table}/{id} - update    - updates columns of a record by primary key
    DELETE /records/{table}/{id} - delete    - deletes a record by primary key
    PATCH  /records/{table}/{id} - increment - increments columns of a record by primary key

The "`/openapi`" endpoint will only show what is allowed in your session. It also has a special 
"document" operation to allow you to hide tables and columns from the documentation.
    
For endpoints that start with "`/columns`" there are the operations "reflect" and "remodel". 
These operations can display or change the definition of the database, table or column. 
This functionality is disabled by default and for good reason (be careful!). 
Add the "columns" controller in the configuration to enable this functionality.

### Authorizing tables, columns and records

By default all tables and columns are accessible. If you want to restrict access to some tables you may add the 'authorization' middleware 
and define a 'authorization.tableHandler' function that returns 'false' for these tables.

    'authorization.tableHandler' => function ($operation, $tableName) {
        return $tableName != 'license_keys';
    },

The above example will restrict access to the table 'license_keys' for all operations.

    'authorization.columnHandler' => function ($operation, $tableName, $columnName) {
        return !($tableName == 'users' && $columnName == 'password');
    },

The above example will restrict access to the 'password' field of the 'users' table for all operations.

    'authorization.recordHandler' => function ($operation, $tableName) {
        return ($tableName == 'users') ? 'filter=username,neq,admin' : '';
    },

The above example will disallow access to user records where the username is 'admin'. 
This construct adds a filter to every executed query. 

NB: You need to handle the creation of invalid records with a validation (or sanitation) handler.

### SQL GRANT authorization

You can alternatively use database permissons (SQL GRANT statements) to define the authorization model. In this case you
should not use the "authorization" middleware, but you do need to use the "reconnect" middleware. The handlers of the
"reconnect" middleware allow you to specify the correct username and password, like this:

    'reconnect.usernameHandler' => function () {
        return 'mevdschee';
    },
    'reconnect.passwordHandler' => function () {
        return 'secret123';
    },

This will make the API connect to the database specifying "mevdschee" as the username and "secret123" as the password.
The OpenAPI specification is less specific on allowed and disallowed operations, when you are using database permissions,
as the permissions are not read in the reflection step.

NB: You may want to retrieve the username and password from the session (the "$_SESSION" variable).

### Sanitizing input

By default all input is accepted and sent to the database. If you want to strip (certain) HTML tags before storing you may add 
the 'sanitation' middleware and define a 'sanitation.handler' function that returns the adjusted value.

    'sanitation.handler' => function ($operation, $tableName, $column, $value) {
        return is_string($value) ? strip_tags($value) : $value;
    },

The above example will strip all HTML tags from strings in the input.

### Validating input

By default all input is accepted. If you want to validate the input, you may add the 'validation' middleware and define a 
'validation.handler' function that returns a boolean indicating whether or not the value is valid.

    'validation.handler' => function ($operation, $tableName, $column, $value, $context) {
        return ($column['name'] == 'post_id' && !is_numeric($value)) ? 'must be numeric' : true;
    },

When you edit a comment with id 4 using:

    PUT /records/comments/4

And you send as a body:

    {"post_id":"two"}

Then the server will return a '422' HTTP status code and nice error message:

    {
        "code": 1013,
        "message": "Input validation failed for 'comments'",
        "details": {
            "post_id":"must be numeric"
        }
    }

You can parse this output to make form fields show up with a red border and their appropriate error message.

### Multi-tenancy support

Two forms of multi-tenancy are supported:

 - Single database, where every table has a tenant column (using the "multiTenancy" middleware).
 - Multi database, where every tenant has it's own database (using the "reconnect" middleware).

Below is an explanation of the corresponding middlewares.

#### Multi-tenancy middleware

You may use the "multiTenancy" middleware when you have a single multi-tenant database. 
If your tenants are identified by the "customer_id" column, then you can use the following handler:

    'multiTenancy.handler' => function ($operation, $tableName) {
        return ['customer_id' => 12];
    },

This construct adds a filter requiring "customer_id" to be "12" to every operation (except for "create").
It also sets the column "customer_id" on "create" to "12" and removes the column from any other write operation.

NB: You may want to retrieve the customer id from the session (the "$_SESSION" variable).

#### Reconnect middleware

You may use the "reconnect" middleware when you have a separate database for each tenant.
If the tenant has it's own database named "customer_12", then you can use the following handler:

    'reconnect.databaseHandler' => function () {
        return 'customer_12';
    },

This will make the API reconnect to the database specifying "customer_12" as the database name. If you don't want
to use the same credentials, then you should also implement the "usernameHandler" and "passwordHandler".

NB: You may want to retrieve the database name from the session (the "$_SESSION" variable).

## Errors

The following errors may be reported:

| Error | HTTP response code         | Message
| ------| -------------------------- | --------------
| 1000  | 404 Not found              | Route not found 
| 1001  | 404 Not found              | Table not found 
| 1002  | 422 Unprocessable entity   | Argument count mismatch 
| 1003  | 404 Not found              | Record not found 
| 1004  | 403 Forbidden              | Origin is forbidden 
| 1005  | 404 Not found              | Column not found 
| 1006  | 409 Conflict               | Table already exists 
| 1007  | 409 Conflict               | Column already exists 
| 1008  | 422 Unprocessable entity   | Cannot read HTTP message 
| 1009  | 409 Conflict               | Duplicate key exception 
| 1010  | 409 Conflict               | Data integrity violation 
| 1011  | 401 Unauthorized           | Authentication required 
| 1012  | 403 Forbidden              | Authentication failed 
| 1013  | 422 Unprocessable entity   | Input validation failed 
| 1014  | 403 Forbidden              | Operation forbidden 
| 1015  | 405 Method not allowed     | Operation not supported 
| 1016  | 403 Forbidden              | Temporary or permanently blocked 
| 1017  | 403 Forbidden              | Bad or missing XSRF token 
| 1018  | 403 Forbidden              | Only AJAX requests allowed 
| 1019  | 403 Forbidden              | Pagination Forbidden 
| 9999  | 500 Internal server error  | Unknown error 

The following JSON structure is used:

    {
        "code":1002,
        "message":"Argument count mismatch in '1'"
    }

NB: Any non-error response will have status: 200 OK

