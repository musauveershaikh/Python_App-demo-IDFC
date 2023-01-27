import mysql.connector
from mysql.connector import errorcode
import datetime
import hvac
import base64
import logging
import time

customer_table = '''
CREATE TABLE IF NOT EXISTS `customers` (
  `Company_ID` VARCHAR(255),
  `First_Name` VARCHAR(70) NOT NULL ,
  `Last_Name` VARCHAR(70) NOT NULL ,
  `Full_Name` VARCHAR(150) NOT NULL ,
  `Employee_Status` VARCHAR(50) ,
  `Gender` VARCHAR(6) ,
  `Date_of_Birth` varchar(255) ,
  `Personal_Email_ID` VARCHAR(255) ,
  `Date_of_Joining` varchar(255) ,
  `Person_Type` VARCHAR(70) NOT NULL ,
  `Designation_Code` INT NOT NULL,
  `Grade_Code` varchar(255) NOT NULL,
  `Location_Code` VARCHAR(255) ,
  `Cost_Centre` CHAR(10) ,
  `Profit_Centre` CHAR(10) ,
  `Business_Profit_Centre` CHAR(10) ,
  `Final_Business_Profit_Centre` CHAR(10) ,
  `Product_Code` varchar(255) ,
  `Reporting_Manager_ID` varchar(255) ,
  `Notice_Period` CHAR(10) ,
  `Retirement_Date` varchar(255) ,
  `Office_Email_ID` VARCHAR(255) ,
  `Resignation_Type` VARCHAR(255) ,
  `Date_of_Resignation` varchar(255) ,
  `Date_of_Leaving` varchar(255) ,
  `Employee_Reason_for_Leaving` VARCHAR(255) ,
  `Manager_Reason_for_Leaving` VARCHAR(255) ,
  `HR_Reason_for_Leaving` VARCHAR(255) ,
  `Resignation_Status` VARCHAR(255) )ENGINE=InnoDB;'''

seed_customers = '''
INSERT IGNORE into customers VALUES
 ('100002','Kandula','Thakur','Kandula Thakur','ACTIVE','M',STR_TO_DATE('14/09/1966', '%d/%m/%Y'),'sendmail-test-discard@oracle.com',STR_TO_DATE('09/01/1989','%d/%m/%Y'),'EMP','2000340','B5','Mumbai-Naman Chambers BKC Corporate Office','1933','999','9999','999','99999','103142','90',STR_TO_DATE('31/01/2023','%d/%m/%Y'),'sendmail-test-discard@oracle.com',' ',STR_TO_DATE('31/01/2023','%d/%m/%Y'),STR_TO_DATE('31/01/2023','%d/%m/%Y'),' ',' ',' ','N/A'),
('100039','BHUNESHWAR','Bhadra','BHUNESHWAR Bhadra','ACTIVE','F',STR_TO_DATE('15/05/1971', '%d/%m/%Y'),'sendmail-test-discard@oracle.com',STR_TO_DATE('17/08/1998','%d/%m/%Y'),'EMP','2000780','B6','Mumbai-Naman Chambers BKC Corporate Office','1109','999','','999','99999','115442','90',STR_TO_DATE('30/09/2025','%d/%m/%Y'),'sendmail-test-discard@oracle.com',' ',STR_TO_DATE('31/01/2023','%d/%m/%Y'),STR_TO_DATE('31/03/2023','%d/%m/%Y'),'Better Profile/Job Role','Personal Reasons',' ','N/A'),
('100041','MANA GOBINDA','KUMAR','MANA GOBINDA KUMAR','ACTIVE','F',STR_TO_DATE('21/01/1947', '%d/%m/%Y'),'',STR_TO_DATE('07/09/1998','%d/%m/%Y'),'EMP','2003206','B4','Mumbai-Naman Chambers BKC Corporate Office','2181','999','','999','99999','115557','90',STR_TO_DATE('31/01/2031','%d/%m/%Y'),'sendmail-test-discard@oracle.com',' ',STR_TO_DATE('31/01/2023','%d/%m/%Y'),STR_TO_DATE('31/01/2023','%d/%m/%Y'),' ',' ',' ','N/A');
'''

logger = logging.getLogger(__name__)

class DbClient:
    conn = None
    vault_client = None
    key_name = None
    mount_point = None
    username = None
    password = None
    is_initialized = False

    #def __init__(self, uri, prt, uname, pw, db):
    #    self.init_db(uri, prt, uname, pw, db)

    def init_db(self, uri, prt, uname, pw, db):
        self.uri = uri
        self.port = prt
        self.username = uname
        self.password = pw
        self.db = db
        self.connect_db(uri, prt, uname, pw)
        cursor = self.conn.cursor()
        logger.info("Preparing database {}...".format(db))
        cursor.execute('CREATE DATABASE IF NOT EXISTS `{}`'.format(db))
        cursor.execute('USE `{}`'.format(db))
        logger.info("Preparing customer table...")
        cursor.execute(customer_table)
        cursor.execute(seed_customers)
        self.conn.commit()
        cursor.close()
        self.is_initialized = True

    # Later we will check to see if this is None to see whether to use Vault or not
    def init_vault(self, addr, token, namespace, path, key_name):
        if not addr or not token:
            logger.warn('Skipping initialization...')
            return
        else:
            logger.warn("Connecting to vault server: {}".format(addr))
            self.vault_client = hvac.Client(url=addr, token=token, namespace=namespace)
            self.key_name = key_name
            self.mount_point = path
            logger.debug("Initialized vault_client: {}".format(self.vault_client))

    def vault_db_auth(self, path):
        try:
            resp = self.vault_client.read(path)
            self.username = resp['data']['username']
            self.password = resp['data']['password']
            logger.debug('Retrieved username {} and password {} from Vault.'.format(self.username, self.password))
        except Exception as e:
            logger.error('An error occurred reading DB creds from path {}.  Error: {}'.format(path, e))

    # the data must be base64ed before being passed to encrypt
    def encrypt(self, value):
        try:
            response = self.vault_client.secrets.transit.encrypt_data(
                mount_point = self.mount_point,
                name = self.key_name,
                plaintext = base64.b64encode(value.encode()).decode('ascii')
            )
            logger.debug('Response: {}'.format(response))
            return response['data']['ciphertext']
        except Exception as e:
            logger.error('There was an error encrypting the data: {}'.format(e))

    # The data returned from Transit is base64 encoded so we decode it before returning
    def decrypt(self, value):
        # support unencrypted messages on first read
        logger.debug('Decrypting {}'.format(value))
        if not value.startswith('vault:v'):
            return value
        else:
            try:
                response = self.vault_client.secrets.transit.decrypt_data(
                    mount_point = self.mount_point,
                    name = self.key_name,
                    ciphertext = value
                )
                logger.debug('Response: {}'.format(response))
                plaintext = response['data']['plaintext']
                logger.debug('Plaintext (base64 encoded): {}'.format(plaintext))
                decoded = base64.b64decode(plaintext).decode()
                logger.debug('Decoded: {}'.format(decoded))
                return decoded
            except Exception as e:
                logger.error('There was an error encrypting the data: {}'.format(e))

    # Long running apps may expire the DB connection
    def _execute_sql(self,sql,cursor):
        try:
            cursor.execute(sql)
            return 1
        except mysql.connector.errors.OperationalError as e:
            if e[0] == 2006:
                logger.error('Error encountered: {}.  Reconnecting db...'.format(e))
                self.init_db(self.uri, self.port, self.username, self.password, self.db)
                cursor = self.conn.cursor()
                cursor.execute(sql)
                return 0

    def connect_db(self, uri, prt, uname, pw):
        logger.debug('Connecting to {} with username {} and password {}'.format(uri, uname, pw))
        for i in range(0,10):
            try:
                self.conn = mysql.connector.connect(user=uname, password=pw, host=uri, port=prt)
            except mysql.connector.Error as err:
                if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                    logger.error("Something is wrong with your user name or password")
                elif err.errno == errorcode.ER_BAD_DB_ERROR:
                    logger.error("Database does not exist")
                else:
                    logger.error(err)
                logger.debug("Sleeping 5 seconds before retry")
                time.sleep(5)
            

    def get_customer_records(self, num = None, raw = None):
        if num is None:
            num = 50
        statement = 'SELECT * FROM `customers` LIMIT {}'.format(num)
        cursor = self.conn.cursor()
        self._execute_sql(statement, cursor)
        results = []
        for row in cursor:
            try:
                r = {}
                r['Company_ID'] = row[0]
                r['First_Name'] = row[1]
                r['Last_Name'] = row[2]
                r['Full_Name'] = row[3]
                r['Employee_Status'] = row[4]
                r['Gender'] = row[5]
                r['Date_of_Birth'] = row[6]
                r['Personal_Email_ID'] = row[7]
                r['Date_of_Joining'] = row[8]
                r['Person_Type'] = row[9]
                r['Designation_Code'] = row[10]    
                r['Grade_Code'] = row[11]  
                r['Location_Code'] = row[12]
                r['Cost_Centre'] = row[13]
                r['Profit_Centre'] = row[14]
                r['Business_Profit_Centre'] = row[15]
                r['Final_Business_Profit_Centre'] = row[16]
                r['Product_Code'] = row[17]
                r['Reporting_Manager_ID'] = row[18]
                r['Notice_Period'] = row[19]
                r['Retirement_Date'] = row[20]
                r['Office_Email_ID'] = row[21]
                r['Resignation_Type'] = row[22]
                r['Date_of_Resignation'] = row[23]
                r['Date_of_Leaving'] = row[24]
                r['Employee_Reason_for_Leaving'] = row[25]
                r['Manager_Reason_for_Leaving'] = row[26]
                r['HR_Reason_for_Leaving'] = row[27]
                r['Resignation_Status'] = row[28]
                if self.vault_client is not None and not raw:
                    r['Product_Code'] = self.decrypt(r['Product_Code'])
                    r['Company_ID'] = self.decrypt(r['Company_ID'])
                    r['Grade_Code'] = self.decrypt(r['Grade_Code'])
                results.append(r)
            except Exception as e:
                logger.error('There was an error retrieving the record: {}'.format(e))
        return results

    def get_customer_record(self, num = None, raw = None):
        statement = 'SELECT * FROM `customers` WHERE cust_no = {}'.format(id)
        cursor = self.conn.cursor()
        self._execute_sql(statement, cursor)
        results = []
        for row in cursor:
            try:
                r = {}
                r['Company_ID'] = row[0]
                r['First_Name'] = row[1]
                r['Last_Name'] = row[2]
                r['Full_Name'] = row[3]
                r['Employee_Status'] = row[4]
                r['Gender'] = row[5]
                r['Date_of_Birth'] = row[6]
                r['Personal_Email_ID'] = row[7]
                r['Date_of_Joining'] = row[8]
                r['Person_Type'] = row[9]
                r['Designation_Code'] = row[10]    
                r['Grade_Code'] = row[11]  
                r['Location_Code'] = row[12]
                r['Cost_Centre'] = row[13]
                r['Profit_Centre'] = row[14]
                r['Business_Profit_Centre'] = row[15]
                r['Final_Business_Profit_Centre'] = row[16]
                r['Product_Code'] = row[17]
                r['Reporting_Manager_ID'] = row[18]
                r['Notice_Period'] = row[19]
                r['Retirement_Date'] = row[20]
                r['Office_Email_ID'] = row[21]
                r['Resignation_Type'] = row[22]
                r['Date_of_Resignation'] = row[23]
                r['Date_of_Leaving'] = row[24]
                r['Employee_Reason_for_Leaving'] = row[25]
                r['Manager_Reason_for_Leaving'] = row[26]
                r['HR_Reason_for_Leaving'] = row[27]
                r['Resignation_Status'] = row[28]
                if self.vault_client is not None:
                    r['Product_Code'] = self.decrypt(r['Product_Code'])
                    r['Company_ID'] = self.decrypt(r['Company_ID'])
                    r['Grade_Code'] = self.decrypt(r['Grade_Code'])
                    r['Date_of_Birth'] = self.decrypt(r['Date_of_Birth'])
                results.append(r)
            except Exception as e:
                logger.error('There was an error retrieving the record: {}'.format(e))
        return results

    def insert_customer_record(self, record):
        if self.vault_client is None:
           statement = '''INSERT INTO `customers` (`Company_ID`, `First_Name`, `Last_Name`,  `Full_Name`,  `Employee_Status`, `Person_Type`, `Designation_Code`,  `Grade_Code`, `Product_Code`) 
                            VALUES  ( "{}", "{}", "{}","{}", "{}", "{}", "{}", "{}", "{}");'''.format(record['Company_ID'],record['First_Name'], record['Last_Name'], record['Full_Name'], record['Employee_Status'], record['Person_Type'], record['Designation_Code'], record['Grade_Code'], record['Product_Code'])
        else:
            statement = '''INSERT INTO `customers` (`Company_ID`, `First_Name`, `Last_Name`,  `Full_Name`,  `Employee_Status`, `Person_Type`, `Designation_Code`,  `Grade_Code`) 
                            VALUES  ( "{}", "{}","{}", "{}", "{}", "{}", "{}", "{}", "{}");'''.format(record['Company_ID'],record['First_Name'], record['Last_Name'], record['Full_Name'], record['Employee_Status'], record['Person_Type'], record['Designation_Code'], self.encrypt(record['Grade_Code']),self.encode_ssn(record['Product_Code']) )
        logger.debug('SQL Statement: {}'.format(statement))
        cursor = self.conn.cursor()
        self._execute_sql(statement, cursor)
        self.conn.commit()
        return self.get_customer_records()

    def update_customer_record(self, record):
        if self.vault_client is None:
            statement = '''UPDATE `customers`
                       SET First_Name  = "{}", Last_Name  = "{}", Full_Name  = "{}", Employee_Status  = "{}", Gender  = "{}", Date_of_Birth  = "{}", Personal_Email_ID  = "{}", Person_Type  = "{}", Designation_Code  = "{}", Grade_Code  = "{}", Location_Code  = "{}", Cost_Centre  = "{}", Profit_Centre  = "{}", Business_Profit_Centre  = "{}", Final_Business_Profit_Centre  = "{}", Gender  = "{}", Product_Code  = "{}", Reporting_Manager_ID  = "{}", Notice_Period  = "{}", Retirement_Date  = "{}", Office_Email_ID  = "{}", Resignation_Type  = "{}", Date_of_Resignation  = "{}", Date_of_Leaving  = "{}", Employee_Reason_for_Leaving  = "{}", Manager_Reason_for_Leaving  = "{}",  HR_Reason_for_Leaving  = "{}", Resignation_Status  = "{}"
                       WHERE Company_ID = {};'''.format(record['Company_ID'], record['First_Name'], record['Last_Name'], record['Full_Name'], record['Employee_Status'], record['Gender'], record['Date_of_Birth'], record['Personal_Email_ID'], record['Person_Type'], record['Designation_Code'], record['Grade_Code'], record['Location_Code'], record['Cost_Centre'], record['Profit_Centre'], record['Business_Profit_Centre'], record['Final_Business_Profit_Centre'], record['Gender'], record['Product_Code'], record['Reporting_Manager_ID'], record['Notice_Period'], record['Retirement_Date'], record['Office_Email_ID'], record['Resignation_Type'], record['Date_of_Resignation'], record['Date_of_Leaving'], record['Employee_Reason_for_Leaving'], record['Manager_Reason_for_Leaving'],  record['HR_Reason_for_Leaving'], record['Resignation_Status']  )
        else:
            statement = '''UPDATE `customers`
                        SET First_Name  = "{}", Last_Name  = "{}", Full_Name  = "{}", Employee_Status  = "{}", Gender  = "{}", Date_of_Birth  = "{}", Personal_Email_ID  = "{}", Person_Type  = "{}", Designation_Code  = "{}", Grade_Code  = "{}", Location_Code  = "{}", Cost_Centre  = "{}", Profit_Centre  = "{}", Business_Profit_Centre  = "{}", Final_Business_Profit_Centre  = "{}", Gender  = "{}", Product_Code  = "{}", Reporting_Manager_ID  = "{}", Notice_Period  = "{}", Retirement_Date  = "{}", Office_Email_ID  = "{}", Resignation_Type  = "{}", Date_of_Resignation  = "{}", Date_of_Leaving  = "{}", Employee_Reason_for_Leaving  = "{}", Manager_Reason_for_Leaving  = "{}",  HR_Reason_for_Leaving  = "{}", Resignation_Status  = "{}"
                        WHERE Company_ID = {};'''.format(self.encrypt(record['Company_ID'], record['First_Name'], record['Last_Name'], record['Full_Name'], record['Employee_Status'], record['Gender'], record['Date_of_Birth'], record['Personal_Email_ID'], record['Person_Type'], record['Designation_Code'], self.encrypt(record['Grade_Code']), record['Location_Code'], record['Cost_Centre'], record['Profit_Centre'], record['Business_Profit_Centre'], record['Final_Business_Profit_Centre'], record['Gender'], self.encrypt(record['Product_Code']), self.encrypt(record['Reporting_Manager_ID']), record['Notice_Period'], record['Retirement_Date'], record['Office_Email_ID'], record['Resignation_Type'], record['Date_of_Resignation'], record['Date_of_Leaving'], record['Employee_Reason_for_Leaving'], record['Manager_Reason_for_Leaving'],  record['HR_Reason_for_Leaving'], record['Resignation_Status']))
        cursor = self.conn.cursor()
        self._execute_sql(statement, cursor)
        self.conn.commit()
        return self.get_customer_records()