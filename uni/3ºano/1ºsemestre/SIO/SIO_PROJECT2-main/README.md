# Application Security Verification Standard (ASVS)

## 1. Group Members:

| NMec | Name | email | 
|:---: |:---|:---:|
| 108317 | Miguel Aido Miragaia      | [miguelmiragaia@ua.pt](https://github.com/Miragaia)              |
| 108536 | Cristiano Antunes Nicolau | [cristianonicolau@ua.pt](https://github.com/cristiano-nicolau)   |
| 107463 | Pedro Miguel Ribeiro Rei  | [pedrorrei@ua.pt](https://github.com/pedrorrei)                  |
| 97541  | Andre Lourenço Gomes      | [andregomes@ua.pt](https://github.com/andregomes04)              |

## 2. Repository Structures

- **app_org** - Insecure app
    * **backend** - backend script (controller.py)
    * **templates** - frontend scripts (.html)
    * **css** - stylesheet scripts (.css)
    * **scss** - stylesheet scripts (.scss)
    * **js** - javascript scripts (.js)
    * **images** - images (.png, .jpg, .svg, .gif)

- **app_sec** - Secure app
    * **backend** - backend script (controller.py)
    * **templates** - frontend scripts (.html)
    * **css** - stylesheet scripts (.css)
    * **scss** - stylesheet scripts (.scss)
    * **js** - javascript scripts (.js)
    * **images** - images (.png, .jpg, .svg, .gif)

- **analysis** - All documentation to support the project
    * **prints** - directory with all the prints taken for this project
    * **report** - directory with the report in .pdf  
        * [Report.pdf](/analysis/report/Report.pdf)
    * **ASVS** - directory with the ASVS excel list
        * [ASVS-Proj2.xlsx](/analysis/ASVS/ASVS-Proj2.xlsx)
        * **images** - directory with the images used in the report
            * **#2.1.12** - directory for #2.1.12
            * **#2.1.6** - directory for #2.1.6
            * **#2.1.8** - directory for #2.1.8
            * **#2.2.1** - directory for #2.2.1
            * **#2.2.3** - directory for #2.2.3
            * **#3.7.1** - directory for #3.7.1

    

- **README.md** - Guideline document for the project

## 3. Description

- **Introduction:**
    - This project involves the evolution of DETI memorabilia online shop to comply with level 1 Application Security Verification Standard requirements. There are 2 distinct views of the project:
        * **app_org:** Functional and secure online shop acording to the first project.
        * **app_sec:** Functional and secure online shop acording to level 1 Application Security Verification Standard requirements.

- **Objectives** 
    - The principal objective is identifying issues and improve the app according to the issues. 

## 4. ASVS List

List of ASVS items that we use have in our project:

-  2.1.1 
-  2.1.2
-  2.1.6
-  2.1.8
-  2.1.9
-  2.1.12
-  2.2.1
-  2.2.2
-  2.2.3
-  2.5.4
-  2.7.2
-  2.7.3
-  2.8.1
-  3.7.1
-  7.1.1
-  7.1.2
-  14.2.2


## 5. How to run

1. pip install -r requirements
2. Run the backend Server:
    - app_org: Directory: /app_org/backend "python3 controller.py"
    - app_sec: Directory: /app_sec/backend "python3 controller.py"
3. If app_sec:
    - Insert database password: "password"
4. Lauch HTML Server:
    - **Option 1**: Using a vscode extension (Live Server), open the file "index.html" in the folder "templates" and click on "Go Live" at the bottom right corner.
    - **Option 2**: Lauch a python server in the folder "2ND-PROJECT-GROUP_13" using the command "python3 -m http.server 5500" and open the browser in the url:
        - app_org: "http://127.0.0.0:5500/app_org/templates/index.html"
        - app_sec: "http://127.0.0.0:5500/app_sec/templates/index.html
    - **Option 3**: Lauch a node server in the folder "2ND-PROJECT-GROUP_13", install using "npm install -g http-server" and run with the command "npx http-server -p 5500", open the browser in the url:
        - app_org: "http://127.0.0.0:5500/app_org/templates/index.html"
        - app_sec: "http://127.0.0.0:5500/app_sec/templates/index.html

## 6. Notes

- **Requirements**
    ```
        flask-sqlalchemy
        flask-cors
        Flask-Bcrypt
        Flask-Login
        PyJWT
        bleach
        werkzeug~=2.2.0
        markupsafe==2.1.1
        SQLAlchemy==1.4.23
        Flask==2.2.0
        jinja2~=3.0.3
        pyotp
        flask-mail
    ```

- **Test Accounts**
    * **app_org**
        - User
            ```
            email: usersec@example.com
            password: Password123!
            ```
        - Administrator:
            ```
            email: adminsec@example.com
            password: Password123!
            ```

    * **app_sec**
        - User
            ```
            email: zepedro@email.com
            password: 123456789pass
            ```
        - Administrator:
            ```
            email: joaopaulo@detistore.com
            password: 123456789pass
            ```
