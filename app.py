from flask import Flask, request, jsonify
import paramiko
import time
import schedule
from threading import Thread
from cryptography.fernet import Fernet
import json
import os
from datetime import datetime

app = Flask(__name__)

# 数据文件路径
DATA_DIR = 'data'
DATA_FILE = os.path.join(DATA_DIR, 'hosts.json')
HISTORY_FILE = os.path.join(DATA_DIR, 'history.json')
ALERTS_FILE = os.path.join(DATA_DIR, 'alerts.json')
KEY_FILE = os.path.join(DATA_DIR, 'key.key')

# 初始化数据存储
hosts = []
metrics = []
history_metrics = []
alerts = []

# 默认告警阈值
current_thresholds = {'cpu': 80, 'mem': 90, 'disk': 90}

# 密码加密初始化 - 修复密钥文件处理
def init_fernet():
    # 确保数据目录存在
    os.makedirs(DATA_DIR, exist_ok=True)
    
    if os.path.exists(KEY_FILE) and os.path.isfile(KEY_FILE):
        # 密钥文件存在且是文件
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
        print("使用现有的密钥文件")
    else:
        # 生成新密钥
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        print("生成新的密钥文件")
    
    return Fernet(key)

fernet = init_fernet()

# 数据持久化函数
def load_data():
    global hosts, history_metrics, alerts, current_thresholds
    try:
        # 加载主机列表
        if os.path.exists(DATA_FILE) and os.path.isfile(DATA_FILE):
            with open(DATA_FILE, 'r', encoding='utf-8') as f:
                hosts = json.load(f)
        
        # 加载历史数据
        if os.path.exists(HISTORY_FILE) and os.path.isfile(HISTORY_FILE):
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                history_metrics = json.load(f)
        
        # 加载告警数据
        if os.path.exists(ALERTS_FILE) and os.path.isfile(ALERTS_FILE):
            with open(ALERTS_FILE, 'r', encoding='utf-8') as f:
                alerts_data = json.load(f)
                alerts = alerts_data.get('alerts', [])
                current_thresholds = alerts_data.get('thresholds', current_thresholds)
                
        print(f"数据加载成功: {len(hosts)}台主机, {len(history_metrics)}条历史记录")
    except Exception as e:
        print(f"加载数据失败: {str(e)}")
        # 初始化空数据
        hosts = []
        history_metrics = []
        alerts = []

def save_data():
    try:
        # 保存主机列表
        with open(DATA_FILE, 'w', encoding='utf-8') as f:
            json.dump(hosts, f, ensure_ascii=False, indent=2)
        
        # 保存历史数据（只保留最近1000条防止文件过大）
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history_metrics[-1000:], f, ensure_ascii=False, indent=2)
        
        # 保存告警数据和阈值
        alerts_data = {
            'alerts': alerts[-100:],  # 只保留最近100条告警
            'thresholds': current_thresholds,
            'last_save': datetime.now().isoformat()
        }
        with open(ALERTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(alerts_data, f, ensure_ascii=False, indent=2)
            
    except Exception as e:
        print(f"保存数据失败: {str(e)}")

# 初始化时加载数据
load_data()

@app.route('/add_host', methods=['POST'])
def add_host():
    try:
        ip = request.form.get('ip')
        user = request.form.get('user')
        pwd = request.form.get('pwd')
        port = request.form.get('port', 22)
        
        # 验证必填字段
        if not ip or not user or not pwd:
            return "错误：请填写所有必填字段！", 400
        
        # 检查是否已存在相同IP的主机
        if any(h["ip"] == ip for h in hosts):
            return "错误：该主机IP已存在！", 400
        
        # 加密密码
        encrypted_pwd = fernet.encrypt(pwd.encode()).decode()
        
        # 添加主机
        host_info = {
            "ip": ip, 
            "user": user, 
            "pwd": encrypted_pwd, 
            "port": int(port),
            "add_time": datetime.now().isoformat()
        }
        hosts.append(host_info)
        
        # 保存数据
        save_data()
        
        return "添加成功！<a href='/'>返回</a>"
    except Exception as e:
        return f"添加失败：{str(e)}", 500

@app.route('/delete_host')
def delete_host():
    try:
        ip = request.args.get('ip')
        global hosts
        hosts = [h for h in hosts if h["ip"] != ip]
        
        # 保存数据
        save_data()
        
        return "删除成功！<a href='/'>返回</a>"
    except Exception as e:
        return f"删除失败：{str(e)}", 500

@app.route('/get_hosts')
def get_hosts():
    # 返回主机列表（不包含密码）
    safe_hosts = []
    for host in hosts:
        safe_host = host.copy()
        safe_host.pop('pwd', None)  # 移除密码字段
        safe_hosts.append(safe_host)
    return jsonify(safe_hosts)

def collect_data(host):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        decrypted_pwd = fernet.decrypt(host["pwd"].encode()).decode()
        
        # 连接SSH
        ssh.connect(
            hostname=host["ip"],
            username=host["user"],
            password=decrypted_pwd,
            port=host["port"],
            timeout=10,
            banner_timeout=20
        )
        
        # 采集CPU使用率
        stdin, stdout, stderr = ssh.exec_command('top -bn1 | grep "Cpu(s)" | awk \'{print $2}\' | cut -d\'%\' -f1')
        cpu_output = stdout.read().decode().strip()
        cpu_value = float(cpu_output) if cpu_output and cpu_output.replace('.', '').isdigit() else 0.0
        cpu = f"{cpu_value:.1f}%"
        
        # 采集内存使用率
        stdin, stdout, stderr = ssh.exec_command('free | grep Mem | awk \'{printf "%.1f", $3/$2*100}\'')
        mem_output = stdout.read().decode().strip()
        mem_value = float(mem_output) if mem_output and mem_output.replace('.', '').isdigit() else 0.0
        mem = f"{mem_value:.1f}%"
        
        # 采集磁盘使用率（根分区）
        stdin, stdout, stderr = ssh.exec_command('df / | tail -1 | awk \'{print $5}\' | sed \'s/%//\'')
        disk_output = stdout.read().decode().strip()
        disk_value = float(disk_output) if disk_output and disk_output.replace('.', '').isdigit() else 0.0
        disk = f"{disk_value:.1f}%"
        
        # 采集网络带宽（简化版，实际项目中可能需要更复杂的计算）
        stdin, stdout, stderr = ssh.exec_command('cat /proc/net/dev | grep eth0 | awk \'{print $2}\'')
        net_rx = stdout.read().decode().strip()
        net_value = float(net_rx) / 1024 / 1024 if net_rx and net_rx.isdigit() else 0.0  # 转换为MB
        net = f"{net_value:.2f} MB"
        
        ssh.close()
        
        return {
            "ip": host["ip"], 
            "cpu": cpu, 
            "mem": mem, 
            "disk": disk,
            "net": net,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except Exception as e:
        print(f"采集 {host['ip']} 数据失败: {str(e)}")
        return {
            "ip": host["ip"], 
            "cpu": "连接失败", 
            "mem": "连接失败", 
            "disk": "连接失败",
            "net": "连接失败",
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

@app.route('/get_metrics')
def get_metrics():
    global metrics
    try:
        # 并行采集所有主机数据（简化版，实际可用线程池）
        metrics = [collect_data(h) for h in hosts]
        return jsonify(metrics)
    except Exception as e:
        print(f"获取监控数据失败: {str(e)}")
        return jsonify([])

def check_alerts(data, thresholds):
    """检查并生成告警"""
    new_alerts = []
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        if data["cpu"] != "连接失败":
            cpu_value = float(data["cpu"][:-1])
            if cpu_value > thresholds['cpu']:
                new_alerts.append({
                    "ip": data["ip"], 
                    "type": "CPU告警", 
                    "value": data["cpu"], 
                    "threshold": thresholds['cpu'],
                    "level": "alert",
                    "time": current_time
                })
            elif cpu_value > thresholds['cpu'] * 0.8:
                new_alerts.append({
                    "ip": data["ip"], 
                    "type": "CPU警告", 
                    "value": data["cpu"], 
                    "threshold": thresholds['cpu'],
                    "level": "warning", 
                    "time": current_time
                })
        
        if data["mem"] != "连接失败":
            mem_value = float(data["mem"][:-1])
            if mem_value > thresholds['mem']:
                new_alerts.append({
                    "ip": data["ip"], 
                    "type": "内存告警", 
                    "value": data["mem"], 
                    "threshold": thresholds['mem'],
                    "level": "alert",
                    "time": current_time
                })
            elif mem_value > thresholds['mem'] * 0.8:
                new_alerts.append({
                    "ip": data["ip"], 
                    "type": "内存警告", 
                    "value": data["mem"], 
                    "threshold": thresholds['mem'],
                    "level": "warning", 
                    "time": current_time
                })
        
        if data["disk"] != "连接失败":
            disk_value = float(data["disk"][:-1])
            if disk_value > thresholds['disk']:
                new_alerts.append({
                    "ip": data["ip"], 
                    "type": "磁盘告警", 
                    "value": data["disk"], 
                    "threshold": thresholds['disk'],
                    "level": "alert",
                    "time": current_time
                })
            elif disk_value > thresholds['disk'] * 0.8:
                new_alerts.append({
                    "ip": data["ip"], 
                    "type": "磁盘警告", 
                    "value": data["disk"], 
                    "threshold": thresholds['disk'],
                    "level": "warning", 
                    "time": current_time
                })
                
    except Exception as e:
        print(f"检查告警失败: {str(e)}")
    
    return new_alerts

def auto_collect():
    """定时自动采集数据"""
    if not hosts:
        return
        
    print(f"开始自动采集 {len(hosts)} 台主机数据...")
    
    for host in hosts:
        try:
            data = collect_data(host)
            
            # 保存到历史数据
            history_metrics.append(data)
            
            # 检查告警
            new_alerts = check_alerts(data, current_thresholds)
            if new_alerts:
                alerts.extend(new_alerts)
                print(f"发现 {len(new_alerts)} 条新告警")
            
        except Exception as e:
            print(f"自动采集 {host['ip']} 失败: {str(e)}")
    
    # 保存数据
    save_data()

def start_schedule():
    """启动定时任务"""
    # 每10秒执行一次自动采集
    schedule.every(10).seconds.do(auto_collect)
    
    # 每5分钟保存一次数据（冗余备份）
    schedule.every(5).minutes.do(save_data)
    
    print("定时任务已启动")
    
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except Exception as e:
            print(f"定时任务执行异常: {str(e)}")
            time.sleep(10)

@app.route('/get_alerts')
def get_alerts():
    try:
        # 支持前端传递阈值参数
        thresholds_param = request.args.get('thresholds')
        if thresholds_param:
            thresholds = json.loads(thresholds_param)
            # 更新阈值并重新检查最近的数据
            global current_thresholds
            current_thresholds.update(thresholds)
        
        # 返回最近的告警（按时间倒序）
        recent_alerts = sorted(alerts, key=lambda x: x['time'], reverse=True)[:20]
        return jsonify(recent_alerts)
    except Exception as e:
        print(f"获取告警失败: {str(e)}")
        return jsonify([])

@app.route('/save_thresholds', methods=['POST'])
def save_thresholds():
    """保存告警阈值"""
    try:
        data = request.get_json()
        if data:
            global current_thresholds
            current_thresholds.update(data)
            save_data()
            return jsonify({"status": "success", "message": "阈值保存成功"})
        return jsonify({"status": "error", "message": "无效的数据"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route('/get_history', methods=['POST'])
def get_history():
    try:
        ip = request.form.get('ip')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        
        if not ip or not start_time:
            return jsonify({"error": "缺少必要参数"}), 400
        
        # 过滤历史数据
        result = []
        for item in history_metrics:
            if (item["ip"] == ip and 
                item["time"].startswith(start_time) and
                (not end_time or item["time"] <= end_time + " 23:59:59")):
                result.append(item)
        
        # 按时间倒序返回
        result.sort(key=lambda x: x['time'], reverse=True)
        return jsonify(result[:100])  # 最多返回100条
        
    except Exception as e:
        print(f"查询历史数据失败: {str(e)}")
        return jsonify([])

@app.route('/export_history')
def export_history():
    """导出历史数据（简化版）"""
    try:
        ip = request.args.get('ip')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        
        if not ip:
            return "请选择主机", 400
        
        # 在实际项目中，这里可以生成CSV文件
        # 这里简化返回JSON数据
        filtered_data = [
            item for item in history_metrics 
            if item["ip"] == ip and 
            (not start_time or item["time"].startswith(start_time))
        ]
        
        return jsonify({
            "filename": f"monitor_data_{ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "data": filtered_data,
            "count": len(filtered_data)
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/')
def index():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"页面加载失败: {str(e)}", 500

@app.route('/health')
def health_check():
    """健康检查接口"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "hosts_count": len(hosts),
        "history_count": len(history_metrics),
        "alerts_count": len(alerts)
    })

# 启动应用
if __name__ == '__main__':
    # 启动定时任务线程
    schedule_thread = Thread(target=start_schedule, daemon=True)
    schedule_thread.start()
    
    print("服务器监控系统启动成功！")
    print(f"监控主机数量: {len(hosts)}")
    print("访问地址: http://localhost:5000")
    
    # 启动Flask应用
    app.run(host='0.0.0.0', port=5000, debug=False)
