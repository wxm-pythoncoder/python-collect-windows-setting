# _*_ coding:utf-8 _*_
import subprocess
import os
import wmi
import socket
import shutil
import winreg
import subprocess
import time
#create dir to collect
dirname = "D:\\collect_tmp"
if not os.path.exists(dirname):
    os.mkdir(dirname)
#get global wmi info
mywmi = wmi.WMI()
#log
#collect_log=open("D:\\log.txt",'w+')


# create powershell and excute
def excuteps(file,cmd):
    filepath = dirname+"\\"+file+".ps1"
    with open(filepath,"w") as f:
        f.write(cmd)
    args = [r"powershell",filepath]
    p = subprocess.Popen(args,stdout=subprocess.PIPE)
    p.communicate()
    return p

#1####系统信息补丁信息
def getpatch():
    #args=[r"C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe","-ExecutionPolicy","Unrestricted","Get-HotFix | Select HotFixID > "+dirname+"\\Systeminfo.txt"]
    result = excuteps("patch","Get-HotFix | Select HotFixID")
    print("||||patch_out||||")
    for i in result.stdout.readlines():
        i = i.decode('GBK','ignore')
        if "KB" in i:
            print(i)


# 2###CPU类型和内存信息
def getCpuMem():
    print("||||cpu_out||||")
    for processor in mywmi.Win32_Processor():
         cpuid_out = processor.DeviceID
         #cpuname_out = processor.Name.strip()
         print(cpuid_out)
    print("||||mem_out||||")
    for Memory in mywmi.Win32_PhysicalMemory():
         mem_out = (int(Memory.Capacity)/1048576)
         print(mem_out)


# 3###磁盘及使用率信息
def getdisk():
    print("||||disk_out||||")
    # for physical_disk in mywmi.Win32_DiskDrive ():
    #     for partition in physical_disk.associators("Win32_DiskDriveToDiskPartition"):
    #         for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
    #             print(physical_disk.Caption.encode("UTF8"), partition.Caption.encode("UTF8"), logical_disk.Caption)
    print("盘符 总大小 空闲率")
    for disk in mywmi.Win32_LogicalDisk(DriveType=3):
        print(disk.Caption, str(round(int(disk.Size)/1073741824))+"G","%0.2f%% free" % (100.0 * float(disk.FreeSpace) / float (disk.Size)))


# 4###操作系统版本等基本信息
def getbaseinfo():
    hostname_out = socket.gethostname()
    f = open(dirname + '\\osverion.txt', 'w+')
    print("|||hostname_out|||")
    print("%s" % hostname_out)
    for interface in mywmi.Win32_NetworkAdapterConfiguration(IPEnabled=1):
            mac_out=interface.MACAddress
            print("|||mac_out|||")
            print("MAC: %s" % mac_out)
            for ip_address in interface.IPAddress:
                ip_out = interface.IPAddress
                print("|||ip_out|||")
                print("ip_add: %s" % ip_out)
#   #获取操作系统版本
    for sys in mywmi.Win32_OperatingSystem():
        print("|||osversion_out|||")
        result = 'sys.Caption.encode("UTF8")'
        f.write(result)
        print(f.read())
    f.close()


#5#### 操作系统路由信息
def getroute():
    result = subprocess.Popen('netstat -rn > '+ dirname + '\\netstat.txt', shell=True, stdout=subprocess.PIPE)
    result.wait()
    print("||||route_out||||")
    f = open(dirname + "\\netstat.txt")
    for line in f.readlines():
        if not (line.__contains__('====') or line == '\n' or line.__contains__('接口列表') ):
            print(line.strip("\r\n"))
    f.close()


#6#####读host文件并输出\读services文件并输出
def getHostsSevices():
    f = open("C:\Windows\System32\drivers\etc\hosts")
    print("||||hosts_conf||||")
    lines = f.readlines()
    for line in lines:
        if line.__contains__('#'):
            continue
        print(line)
    print("\r\n")
    f.close()


    # 输出services内容
    f1 = open("C:\Windows\System32\drivers\etc\services")
    print("|||services_conf|||")
    lines = f1.readlines()
    for line in lines:
        if line.__contains__('#'):
            continue
        print(line)
    f1.close()


#7#####操作系统应用服务信息
def getservice():
    print("||||service_out||||")
    for s in mywmi.Win32_Service():
        print(s.Caption, s.State)


#8###操作系统用户和组信息
def getuser():
    result = subprocess.Popen('net user > '+ dirname + '\\netuser.txt', shell=True, stdout=subprocess.PIPE)
    result.wait()
    print("||||user_out||||")
    f = open(dirname + "\\netuser.txt")
    for line in f.readlines():
        if not (line.__contains__("命令") or line.__contains__("用户") or line.__contains__('/\r/\n') or line == '\n' or line.__contains__('-----')):
            print(line.strip("\r\n"))
    f.close()
    result.kill()


def getgroup():
    result = subprocess.Popen('net localgroup > ' + dirname + '\\netgroup.txt', shell=True, stdout=subprocess.PIPE)
    result.wait()
    print("||||group_out||||")
    f1 = open(dirname + "\\netgroup.txt")
    for line in f1.readlines():
        if not (line.__contains__("命令") or line.__contains__("别名") or line.__contains__('/\r/\n') or line == '\n' or line.__contains__('-----')):
            print(line.strip("\r\n").strip('*'))
    f1.close()
    result.kill()


#9####Administrator计划任务
def gettask():
    task_out = os.popen("SCHTASKS /Query")
    print("||||task_out||||")
    print("task_out")
    task_out.close()


#10#####已安装程序
def getprogram():
    file = open(dirname+"\\program.txt", "a+")
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    try:
        i = 0
        while 1:
            name = winreg.EnumKey(key,i)
            if name.__contains__('{'):
                file.write('')
            else:
                file.write(name + '\r\n')
            i+=1
    except WindowsError:
        print()

    key1 = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
    try:
        j = 0
        while 1:
            name1 = winreg.EnumKey(key1, j)
            if name1.__contains__('{'):
                file.write('')
            else:
                file.write(name1 + '\r\n')
            j += 1
    except WindowsError:
        print()
    file.close()
    print("|||program_out||||")
    f = open(dirname+"\\program.txt","r")
    lines = f.readlines()
    for line in lines:
        if line =='\n':
            continue
        print(line.strip())
    f.close()


#11#####已安装组件#调用本地powershell
def getmodule():
    print("|||moudle_out||||")
    try:
        result = excuteps("moudle", "Get-WindowsFeature")
        for i in result.stdout.readlines():
            i = i.decode('GBK', 'ignore')
            print(i)
    except :
        print("该操作系统版本不支持")



#12####群集资源信息
def getcluster():
    print("||||cluster_out||||")
    try:
        result = excuteps("cluster", "Get-clusterResource")
        for i in result.stdout.readlines():
            i = i.decode('GBK', 'ignore')
            print(i)
    except :
        print("该主机是单机")


if __name__ == '__main__':
    print("开始收集windows配置比对信息")
    start = time.time()
    getpatch()
    getCpuMem()
    getdisk()
    getbaseinfo()
    getroute()
    getHostsSevices()
    getservice()
    getuser()
    getgroup()
    gettask()
    getprogram()
    getmodule()
    getcluster()
    shutil.rmtree(dirname)
    end = time.time()
    print('程序一共花费%s的时间' % (end - start))
    print("windows配置比对信息收集完成")
