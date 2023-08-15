import datetime
import hashlib
import os
import time

import winbio


# Configuration
DATABASE_FILE = 'attendance.db'
HASH_SALT = '7e33a71f-2997-4a07-b2f8-3be9e2abf4ad'


def create_database():
    if os.path.exists(DATABASE_FILE):
        return

    with open(DATABASE_FILE, 'w') as f:
        f.write('')


def hash_id(id):
    h = hashlib.sha256()
    h.update((id + HASH_SALT).encode())
    return h.hexdigest()


def add_attendance(id):
    with open(DATABASE_FILE, 'a') as f:
        f.write(f'{hash_id(id)},{datetime.datetime.now()}\n')


def get_attendance(id):
    with open(DATABASE_FILE, 'r') as f:
        lines = f.readlines()

    return [line.strip().split(',') for line in lines if line.startswith(hash_id(id))]


def main():
    create_database()

    fp = winbio.FingerPrint()

    while True:
        fp.open()
        fp.locate_unit()

        try:
            fp.identify()
            id = fp.identity.Value.AccountSid.Data[:fp.identity.Value.AccountSid.Size].decode('utf-8')
            add_attendance(id)
            print(f'Attendance recorded for {id}')
        except Exception as e:
            print(e)

        fp.close()

        time.sleep(1)


if __name__ == '__main__':
    main()
