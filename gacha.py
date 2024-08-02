import configparser
import os
import platform
import re
from urllib.parse import parse_qsl, urlparse, urljoin, urlencode
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 注册表键前缀
reg_key_prefix = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'
reg_key_cn = reg_key_prefix + '崩坏：星穹铁道'
api_domain = 'https://api-takumi.mihoyo.com'
# 适配新的匹配模式，先从 webview URL 中提取 authkey 等参数
api_pattern = re.compile(r'https://webstatic\.mihoyo\.com/.+?authkey=[^&]+&game_biz=[^&]+')

# 检测游戏安装路径
def detect_game_install_path():
    logger.info('Detecting game install path')
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_key_cn) as rk:
            install_path = winreg.QueryValueEx(rk, 'InstallPath')[0]
        config_path = os.path.join(install_path, 'config.ini')
        parser = configparser.ConfigParser()
        parser.read(config_path)
        game_install_path = parser.get('launcher', 'game_install_path')
        if not os.path.exists(game_install_path):
            error_msg = (
                f'Game install path {game_install_path} does not exist. '
                'Please check whether the game is installed correctly.'
            )
            logger.error(error_msg)
            return None
        return game_install_path
    except Exception as e:
        logger.error(f"Failed to detect game install path: {e}")
        return None

# 获取最新的版本文件夹路径
def get_latest_version_folder(base_cache_path):
    versions = []
    pattern = re.compile(r'[\d.]+$')
    for subdir in os.listdir(base_cache_path):
        path = os.path.join(base_cache_path, subdir)
        if os.path.isdir(path) and re.match(pattern, subdir):
            versions.append((subdir, os.path.getmtime(path)))
    if not versions:
        return None
    # 按最后修改时间排序，取最新的文件夹
    latest_version = max(versions, key=lambda x: x[1])[0]
    return os.path.join(base_cache_path, latest_version)

# 获取缓存路径
def get_cache_path(game_install_path):
    logger.info('Getting gacha query cache path')
    base_cache_path = os.path.join(
        game_install_path, 'StarRail_Data', 'webCaches',
    )
    latest_version_folder = get_latest_version_folder(base_cache_path)
    if latest_version_folder:
        return os.path.join(
            latest_version_folder, 'Cache', 'Cache_Data', 'data_2',
        )
    else:
        return None

# 从文本中提取URL
def get_url_from_text(text):
    if not text:
        return None
    urls = re.findall(api_pattern, text)
    if not urls:
        return None
    return urls

# 安全转换为整数
def safe_int(value, default_value=0):
    try:
        return int(value)
    except Exception:
        return default_value

# 从URL中获取时间戳
def get_timestamp_from_url(url):
    parsed = urlparse(url)
    query_dict = dict(parse_qsl(parsed.query))
    timestamp = query_dict.get('timestamp', 0)
    return safe_int(timestamp)

# 构建 API URL
def construct_api_url(base_url, query_dict):
    return f"{base_url}/common/gacha_record/api/getGachaLog?{urlencode(query_dict)}"

# 检查authkey的有效性
def check_authkey_validity(api_url):
    try:
        # 发送测试请求来验证authkey的有效性
        response = requests.get(api_url)
        data = response.json()
        if data.get("retcode") == -101:
            logger.error("authkey timeout, please refresh by visiting the gacha log page in the game.")
            return None
        return api_url  # 返回验证成功的 URL
    except Exception as e:
        logger.error(f"Failed to check authkey validity: {e}")
        return None

# 从缓存中获取API URL
def get_api_from_cache(cache_path):
    logger.info('Getting API URL from cache')
    try:
        with open(cache_path, 'rb') as f_cache:
            cache = f_cache.read()

        # Debug: 打印缓存文件路径和内容预览
        logger.debug(f"Cache file path: {cache_path}")
        logger.debug(f"Cache content preview: {cache[:1000]}")

        parts = cache.split(b'1/0/')
        parts = [part.split(b'\x00')[0].decode(errors='ignore') for part in parts]
        urls = []
        for part in parts:
            url_list = get_url_from_text(part)
            if url_list:
                urls.extend(url_list)

        if not urls:
            error_msg = (
                'API URL not found in cache. Please visit the gacha querying '
                'page before exporting gacha data.'
            )
            logger.error(error_msg)
            return None

        valid_url = None
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_authkey_validity, construct_api_url(api_domain, dict(parse_qsl(urlparse(url).query)))) for url in urls]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    valid_url = result
                    break  # 找到一个有效的 URL 就停止

        return valid_url
    except Exception as e:
        logger.error(f"Failed to get API URL from cache: {e}")
        return None

# 自动检测API URL
def detect_api_url():
    if platform.system() == 'Windows':
        logger.info('Trying to auto-detect API URL')
        game_install_path = detect_game_install_path()
        if game_install_path:
            cache_path = get_cache_path(game_install_path)
            if cache_path:
                return get_api_from_cache(cache_path)
            else:
                logger.error('No valid cache path found.')
                return None
    else:
        logger.error('Auto-detect API URL is only supported on Windows platform.')
        return None

# 测试检测API URL
if __name__ == "__main__":
    api_url = detect_api_url()
    if api_url:
        print(f"Valid API URL: {api_url}")
        # save valid API URL to the file with date in the name
        with open(f"api_url_{safe_int(get_timestamp_from_url(api_url))}.txt", "w") as f:
            f.write(api_url)

    else:
        print("Failed to detect any valid API URLs.")
