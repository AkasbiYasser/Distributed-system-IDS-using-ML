import pandas as pd
import hashlib
import joblib
import socket
import threading
import mysql.connector
from mysql.connector import errorcode
from datetime import datetime
from sklearn.preprocessing import LabelEncoder, StandardScaler

class NeuralCoinBlock:
    def __init__(self, previous_block_hash, transaction_list):
        self.previous_block_hash = previous_block_hash
        self.transaction_list = transaction_list
        self.block_data = "-".join(transaction_list) + "-" + previous_block_hash
        self.block_hash = hashlib.sha256(self.block_data.encode()).hexdigest()

class Process:
    def __init__(self):
        self.df = pd.DataFrame()
        self.X_transformed = None
        self.previous_final_hash = None  # Track the previous final hash
        self.load_previous_hash()

    def load_previous_hash(self):
        try:
            connection = mysql.connector.connect(
                user='ids',
                password='ids2024',
                host='localhost',
                database='ids'
            )
            cursor = connection.cursor()
            cursor.execute("SELECT hash FROM hashs ORDER BY timestamp DESC LIMIT 1")
            result = cursor.fetchone()
            if result:
                self.previous_final_hash = result[0]
            cursor.close()
            connection.close()
        except mysql.connector.Error as err:
            print(f"Error loading previous hash: {err}")
        except Exception as e:
            print(f"Error: {e}")

    def load_and_process_data(self):
        try:
            self.df = pd.read_csv("extracted_packets.csv", sep=",", names=[
                "duration", "protocoltype", "service", "flag", "srcbytes", "dstbytes", "wrongfragment", "hot",
                "loggedin", "numcompromised", "rootshell", "suattempted", "numroot", "numfilecreations",
                "numshells", "numaccessfiles", "ishostlogin", "isguestlogin", "count", "srvcount", "serrorrate",
                "srvserrorrate", "rerrorrate", "srvrerrorrate", "samesrvrate", "diffsrvrate", "srvdiffhostrate",
                "dsthostcount", "dsthostsrvcount", "dsthostsamesrvrate", "dsthostdiffsrvrate",
                "dsthostsamesrcportrate", "dsthostsrvdiffhostrate", "dsthostserrorrate", "dsthostsrvserrorrate",
                "dsthostrerrorrate", "dsthostsrvrerrorrate", "lastflag"
            ])

            self.df = self.df.fillna(0)

            le = LabelEncoder()
            self.df['protocoltype'] = le.fit_transform(self.df['protocoltype'])
            self.df['service'] = le.fit_transform(self.df['service'])
            self.df['flag'] = le.fit_transform(self.df['flag'])

            scaler = StandardScaler()
            scaler.fit(self.df)
            self.X_transformed = scaler.transform(self.df)
        except Exception as e:
            print(f"Error processing data: {e}")

    def generate_blockchain_hashes(self):
        try:
            previous_hash = self.previous_final_hash if self.previous_final_hash else "Initial String"
            blocks = []

            for index, row in self.df.iterrows():
                transactions = [str(value) for value in row]
                block = NeuralCoinBlock(previous_hash, transactions)
                blocks.append(block)
                previous_hash = block.block_hash

            self.previous_final_hash = blocks[-1].block_hash if blocks else None
            return self.previous_final_hash
        except Exception as e:
            print(f"Error generating blockchain hashes: {e}")
            return None

    def count_zeros_greater_than_ones(self, arr):
        arr = list(arr)
#        count_zeros = arr.count(0)
#        count_ones = arr.count(1)
#        return count_zeros > count_ones
        if 0 in arr:
            return True
        else:
            return False
    def SVM(self):
        try:
            svm = joblib.load("svm_model.pkl")
            array = svm.predict(self.X_transformed)
            print("SVM:", array)
            c = self.count_zeros_greater_than_ones(array)
            print("The bool of SVM:", c)
            return c
        except Exception as e:
            print(f"Error in SVM prediction: {e}")
            return False

    def rf(self):
        try:
            rf = joblib.load("random_forest_model.pkl")
            array = rf.predict(self.X_transformed)
            print("RF:", array)
            c = self.count_zeros_greater_than_ones(array)
            print("The bool of RF:", c)
            return c
        except Exception as e:
            print(f"Error in Random Forest prediction: {e}")
            return False

    def save_hash_to_db(self, final_hash, remote_ip):
        try:
            connection = mysql.connector.connect(
                user='ids',
                password='ids2024',
                host='localhost',
                database='ids'
            )
            cursor = connection.cursor()

            # Create table if it doesn't exist
            create_table_query = """
            CREATE TABLE IF NOT EXISTS hashs (
                timestamp DATETIME,
                remote_ip VARCHAR(255),
                hash VARCHAR(255)
            )
            """
            cursor.execute(create_table_query)

            # Insert the final hash
            cursor.execute("""
            INSERT INTO hashs (timestamp, remote_ip, hash)
            VALUES (%s, %s, %s)
            """, (datetime.now(), remote_ip, final_hash))

            connection.commit()
            cursor.close()
            connection.close()
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with your user name or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
            else:
                print(err)
        except Exception as e:
            print(f"Error saving hash to database: {e}")

    def save_attack_data_to_db(self, final_hash, remote_ip):
        try:
            connection = mysql.connector.connect(
                user='ids',
                password='ids2024',
                host='localhost',
                database='ids'
            )
            cursor = connection.cursor()

            # Create table if it doesn't exist
            create_table_query = """
            CREATE TABLE IF NOT EXISTS attacks (
                duration FLOAT,
                protocoltype INT,
                service INT,
                flag INT,
                srcbytes INT,
                dstbytes INT,
                wrongfragment INT,
                hot INT,
                loggedin INT,
                numcompromised INT,
                rootshell INT,
                suattempted INT,
                numroot INT,
                numfilecreations INT,
                numshells INT,
                numaccessfiles INT,
                ishostlogin INT,
                isguestlogin INT,
                count INT,
                srvcount INT,
                serrorrate FLOAT,
                srvserrorrate FLOAT,
                rerrorrate FLOAT,
                srvrerrorrate FLOAT,
                samesrvrate FLOAT,
                diffsrvrate FLOAT,
                srvdiffhostrate FLOAT,
                dsthostcount INT,
                dsthostsrvcount INT,
                dsthostsamesrvrate FLOAT,
                dsthostdiffsrvrate FLOAT,
                dsthostsamesrcportrate FLOAT,
                dsthostsrvdiffhostrate FLOAT,
                dsthostserrorrate FLOAT,
                dsthostsrvserrorrate FLOAT,
                dsthostrerrorrate FLOAT,
                dsthostsrvrerrorrate FLOAT,
                lastflag VARCHAR(255),
                remote_ip VARCHAR(255),
                hash VARCHAR(255)
            )
            """
            cursor.execute(create_table_query)

            # Insert data with remote_ip and hash
            insert_query = """
            INSERT INTO attacks (
                duration, protocoltype, service, flag, srcbytes, dstbytes, wrongfragment, hot, loggedin,
                numcompromised, rootshell, suattempted, numroot, numfilecreations, numshells, numaccessfiles,
                ishostlogin, isguestlogin, count, srvcount, serrorrate, srvserrorrate, rerrorrate, srvrerrorrate,
                samesrvrate, diffsrvrate, srvdiffhostrate, dsthostcount, dsthostsrvcount, dsthostsamesrvrate,
                dsthostdiffsrvrate, dsthostsamesrcportrate, dsthostsrvdiffhostrate, dsthostserrorrate,
                dsthostsrvserrorrate, dsthostrerrorrate, dsthostsrvrerrorrate, lastflag, remote_ip, hash
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            for _, row in self.df.iterrows():
                cursor.execute(insert_query, (*row, remote_ip, final_hash))

            connection.commit()
            cursor.close()
            connection.close()
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                print("Something is wrong with your user name or password")
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                print("Database does not exist")
            else:
                print(err)
        except Exception as e:
            print(f"Error saving attack data to database: {e}")

    def log_result(self, remote_ip, status):
        log_entry = f"{datetime.now()}: IP={remote_ip}, STATUS={status}\n"
        with open("processing_log.txt", "a") as log_file:
            log_file.write(log_entry)

    def logic(self, remote_ip):
        try:
            self.load_and_process_data()
            final_hash = self.generate_blockchain_hashes()
            if final_hash:
                self.save_hash_to_db(final_hash, remote_ip)  # Use the provided remote_ip

                if self.rf() or self.SVM():
                    print("There is an attack")
                    self.save_attack_data_to_db(final_hash, remote_ip)
                    self.log_result(remote_ip, "attack")
                    return "attack"
                else:
                    print("No attack detected")
                    self.log_result(remote_ip, "not an attack")
                    return "not an attack"
            else:
                self.log_result(remote_ip, "error generating hash")
                return "error generating hash"
        except Exception as e:
            print(f"Error in logic method: {e}")
            self.log_result(remote_ip, "error")
            return "error"

def handle_message(message, remote_ip):
    if message == "verify":
        process = Process()
        result = process.logic(remote_ip)
        return result
    return "Invalid message"

def start_server():
    host = '0.0.0.0'
    port = 9001

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_socket.bind((host, port))

    # Listen for incoming connections
    server_socket.listen(1)
    print(f"Listening on {host}:{port}")

    while True:
        # Accept a connection
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        remote_ip = client_address[0]  # Get the client's IP address

        # Receive the message
        message = client_socket.recv(1024).decode()

        # Handle the message
        response = handle_message(message, remote_ip)

        # Send the response back to the client
        client_socket.send(response.encode())

        # Close the connection
        client_socket.close()

if __name__ == "__main__":
    start_server()
