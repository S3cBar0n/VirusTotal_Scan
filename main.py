import time
import vt
import os
import hashlib
import pprint
import logging
import datetime

path = ".\Scan"
token = os.getenv("VT_API")
# Initializing the logging service
logging.basicConfig(filename=f'{datetime.date.today()}.log', encoding='utf-8', level=logging.DEBUG)

# Asks user for Virus Total API token if one is not present in environment variables.
if not token:
    token = input("Please enter your Virus Total API Token: ")
else:
    pass


# Function to perform scanning on files that have not been seen on Virus Total before.
def vtScan(scan_entry):
    with open(scan_entry, "rb") as f:
        client = vt.Client(token)
        # Sending file to VT for upload/scan
        analysis = client.scan_file(f)

        # Checks to see the status of the upload and whether its complete.
        while True:
            analysis = client.get_object("/analyses/{}", analysis.id)
            print(f"Current Status: {analysis.status}")
            if analysis.status == "completed":
                client.close()
                break
            else:
                time.sleep(15)
        return


# Our main searches the Scan directory for files and checks their hashes against Virus Total.
def main():
    if os.path.isdir(path):
        with os.scandir(path) as directory:
            for entry in directory:
                # It checks to see if a file has a size, if not it skips the file.
                if os.stat(entry.path).st_size == 0:
                    continue
                else:
                    pass

                with open(entry.path, "rb") as f:
                    client = vt.Client(token)
                    sha_hash = hashlib.sha256()
                    sha_hash.update(f.read())
                    hashed_file = sha_hash.hexdigest()

                    # Checks to see if the file is on VT, if not it sends it to the scan function
                    try:
                        file = client.get_object(f"/files/{hashed_file}")
                    except Exception as e:
                        print(f"File {entry.name} has not been scanned on VT: {e}")
                        logging.warning(f"File {entry.name} has not been scanned on VT: {e}")
                        print("Beginning VT Scan")
                        logging.info(f"Scanning {entry.name} on Virus Total...")
                        vtScan(entry.path)
                        file = client.get_object(f"/files/{hashed_file}")
                        logging.info(f"VT Scan of {entry.name} has completed...")

                    # Printing information VT has collected on this file.
                    scan_details = file.last_analysis_stats

                    print(entry.name)
                    print(hashed_file)
                    pprint.pprint(scan_details)
                    print(f"{file.size} Bytes\n")

                    logging.info(f"File Name: {entry.name}")
                    logging.info(f"File Hash: {hashed_file}")
                    logging.info(f"Scan Results: {scan_details}")
                    logging.info(f"File Size: {file.size} Bytes\n")

                    # Closing our VT connection and the file last scanned.
                    client.close()
                    f.close()
    else:
        print("Scan Folder does not exist in the same folder as this program")
        logging.error("Scan Folder does not exist in the same folder as this program")
        os.mkdir(".\Scan")
        print("Folder has been generated.. Please place files in the directory and re-run the program.")
        logging.info("Folder has been generated.. Please place files in the directory and re-run the program.")
        exit()

    print("Scanning Completed... Exiting...")
    logging.info("Scanning Completed... Exiting...")
    logging.shutdown()


if __name__ == '__main__':
    main()
