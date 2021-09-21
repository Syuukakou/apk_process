import os
import zipfile
import json
import hashlib
import subprocess
import lief, r2pipe
import datetime
import sys
sys.path.append("/home/syuu/Project/apk_process")
import multiprocessing
from multiprocessing import Pool
import signal


def timeout_handler(num, stack):
    print("Received SIGALRM")
    raise Exception("FUBAR")



def get_timeNow():

    return datetime.datetime.utcnow()

def generage_md5(filepath):

    return hashlib.md5(open(filepath, "rb").read()).hexdigest()

def filter_ELF(unzip_folder, apk_elf_folder, apk_name):
    elfFromapk_folder = apk_elf_folder + '/' + apk_name
    if not os.path.exists(elfFromapk_folder):
        os.mkdir(elfFromapk_folder)
    for file in os.listdir(unzip_folder):
        filepath = os.path.join(unzip_folder, file)
        if os.path.isfile(filepath):
            output = subprocess.check_output("file " + filepath, shell=True)
            if "ELF" not in output.decode('utf-8'):
                os.remove(filepath)

            elif "ELF" in output.decode('utf-8'):
                new_name = generage_md5(filepath)
                os.rename(filepath, os.path.join(elfFromapk_folder, new_name))
                print("{} renamed to {}".format(file, new_name))


def getMD5_Architecture(unzip_folder):
    # obtain ELF file's md5 hash and architecture
    ELF_infos = {}
    for file in os.listdir(unzip_folder):
        filepath = os.path.join(unzip_folder, file)
        if os.path.isfile(filepath):
            md5_value = generage_md5(filepath)
            r = r2pipe.open(filepath)
            output = r.cmdj("iIj")
            architecture = output['arch']
            ELF_infos[md5_value] = architecture
            print("{} ----> {}".format(md5_value, architecture))

    return ELF_infos


def extractELF_fromAPK(apk_folder, dst_folder, apk_elf_folder):
    """
    use zipfile to extract ELF from apk
    1. unzip apk to <apk filename> folder
    2. filter the files in the <apk filename> folder, if file type is not ELF, delete the file.
    3. for the extracted ELF, log the file architecture, md5 hash, and the source apk name into file (json or csv).
       apk name:
            ELF file_1: md5 hash, architecture
            ELF file_2: md5 hash, architecture

    Args:
        apk_folder ([type]): [description]
        dst_ELFfolder ([type]): [description]
    """
    apk_ELF_infos = {}
    for curdir, dirs, files in os.walk(apk_folder):
        for file in files:
            filepath = os.path.join(curdir, file)
            if os.path.isfile(filepath):
                apk_name = os.path.basename(filepath).strip('.apk')
                try:
                    output = subprocess.check_output("apktool d -s " + filepath + " -o " + dst_folder + "/" + apk_name, shell=True)
                except subprocess.CalledProcessError as e:
                    with open("files\apktool_errors.txt", "a+") as f:
                        f.write(filepath)
                    print("{} {}".format(get_timeNow(), e))
                # unzip_folder = dst_folder + "/" + apk_name
                # if not os.path.exists(unzip_folder):
                #     os.mkdir(unzip_folder)
                # print("{} To unzip {}".format(get_timeNow(), apk_name))
                # try:
                #     with zipfile.ZipFile(filepath, "r") as zip_ref:
                #         zip_ref.extractall(unzip_folder)
                # except NotADirectoryError as e:
                #     print(e)
                print("{} {} extracted!".format(get_timeNow(), file))
                # filter for ELF file
                print("{} filter for ELF file".format(get_timeNow()))
                unzip_folder = dst_folder + "/" + apk_name
                filter_ELF(unzip_folder, apk_elf_folder, apk_name)
                # obtain ELF file's md5 hash and architecture
                print("{} obtain ELF file's md5 hash and architecture".format(get_timeNow()))
                elfFromapk_folder = apk_elf_folder + '/' + apk_name
                ELF_infos = getMD5_Architecture(elfFromapk_folder)
                apk_ELF_infos[apk_name] = ELF_infos

                print("{} {} processed".format(get_timeNow(), apk_name))
    with open("files/apk_ELF_infos.json", "w") as f:
        json.dump(apk_ELF_infos, f)

def extractELF_fromAPK_1(unzipped_apk):
    elf_infos = {}
    for curDirs, dirs, files in os.walk(unzipped_apk):
        for file in files:
            filepath = os.path.join(curDirs, file)
            if os.path.isfile(filepath):
                output = subprocess.check_output("file " + filepath, shell=True)
                if 'ELF' in output.decode('utf-8') and "1564480_0d7525006d71b06d8f8e394e7cb8219bd418681f6fc9b0007d10872ca8fb8c2c" not in filepath:
                    # and "1564480_0d7525006d71b06d8f8e394e7cb8219bd418681f6fc9b0007d10872ca8fb8c2c" not in filepath
                    # elf_name = os.path.basename(filepath)
                    md5_value = generage_md5(filepath)
                    binary = lief.parse(filepath)
                    architecture = str(binary.header.machine_type).split('.')[1].lower()
                    elf_infos[md5_value] = {"architecture": architecture, "filepath": filepath}
    
    return elf_infos
                    # print(filepath)                     
def multiple_elfExtractor(folder):
    for file in os.listdir(folder):
        folderpath = os.path.join(folder, file)
        if os.path.isdir(folderpath):
            extractELF_fromAPK_1(folderpath)

def test():
    print()
    # filepath = '/home/syuu/04/01/00/1559099_64a96a9c1d041b9c33a850cc5c5c2e79eff16ec404b67cd25cc4c760192821b4.apk'
    # with zipfile.ZipFile(filepath, "r") as zip_ref:
    #     zip_ref.extractall("/home/syuu/test_folder")
    for curDirs, dirs, files in os.walk("/home/syuu/test/1555652_00004295316d5993b4607d230954ab2a5e3cca611f7b4212fb31e5f93585b04f"):
        for file in files:
            filepath = os.path.join(curDirs, file)
            if os.path.isfile(filepath):
                output = subprocess.check_output("file " + filepath, shell=True)
                if "ELF" in output.decode('utf-8'):
                    return filepath
                    # print(file)
    # for 
    

if __name__ == '__main__':
    # extractELF_fromAPK("/home/syuu/04", "/home/syuu/unzip_apk", "/home/syuu/apk_elf")
    # test()
    # extractELF_fromAPK_1()
    # multiple_elfExtractor("/home/syuu/unzip_apk")

    unzip_apk = "/home/syuu/unzip_apk"
    statistics_results = {}
    # p = Pool(6)
    for folder in os.listdir(unzip_apk):
        folderpath = os.path.join(unzip_apk, folder)
        if os.path.isdir(folderpath):
            apk_name = folderpath.strip('/home/syuu/unzip_apk/')
            print(apk_name)
            # elf_infos = extractELF_fromAPK_1(folderpath)
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(60)
            try:
                # p_out = p.apply_async(extractELF_fromAPK_1, [folderpath])
                elf_infos = extractELF_fromAPK_1(folderpath)
                # statistics_results[apk_name] = elf_infos
                with open("files/apk_extractedELF_2.json", "a+") as f:
                    json.dump({apk_name: elf_infos}, f)
                print(elf_infos)
            except Exception as e:
                print(folderpath, " Timeout Error")
                with open("files/timeout_error_2.txt", "a+") as f:
                    f.write("%s\n" % folderpath)
            finally:
                signal.alarm(60)
                print("reset alarm")
    # with open("files\apk_extractedELF.json", "w") as f:
    #     json.dump(statistics_results, f)