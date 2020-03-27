#coding=utf-8
import re
import zlib
import cv2
from scapy.all import *

pictures_directory = "./pictures/"
faces_directory = "./faces/"
pcap_file = "arper.pcap"

# get_http_headers()处理原始的 HTTP 流，使用正则表达式对头部进行了分割。
def get_http_headers(http_payload):
    try:
        #如果为http流量，提取http头
        headers_raw = http_payload[:http_payload.index("\r\n\r\n")+2]

        #对http头进行切分
        headers = dict(re.findall(r"(?P<name>.*?):(?P<value>.*?)\r\n", headers_raw))

    except:
        return None

    if "Content-Type" not in headers:
        return None

    return headers

# extract_image() 解析 HTTP 头，检测 HTTP 响应中是都包含图像文件。
def extract_image(headers, http_payload):
    image = None
    image_type = None

    try:
		# 如果检测到 Content-Type 字段中包含 image 的 MIME 类型，则对字段值进行分割，提取图像类型
        if "image" in headers['Content-Type']:
            #获取图像类型和图像数据
            image_type = headers['Content-Type'].split("/")[1]
            image = http_payload[http_payload.index("\r\n\r\n")+4:]
            #如果数据进行了压缩则解压
            try:
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        image = zlib.decompress(image, 16+zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == "deflate":
                        image = zlib.decompress(image)
            except:
                pass
    except:
        return None, None

    return image,image_type

def face_detect(path, file_name):
	# 读取图像
    img = cv2.imread(path)
	# 对图像进行分类算法检测，此处只能检测正面。有的分类算法可以检测侧面
    cascade = cv2.CascadeClassifier("haarcascade_frontalface_alt.xml")
    rects = cascade.detectMultiScale(img, 1.3, 4, cv2.cv.CV_HAAR_SCALE_IMAGE, (20,20))

    if len(rects) == 0:
        return False

    rects[:, 2:] += rects[:, :2]

    # 对图像中的人脸进行高亮的显示处理
	# 检测到人脸后，会返回图像人脸所在的一个长方形的区域。
    for x1, y1, x2, y2 in rects:
        cv2.rectangle(img, (x1,y1), (x2,y2), (127,255,0), 2)
	# 将结果写入文件
    cv2.imwrite("%s／%s-%s" (faces_directory, pcap_file, file_name), img)
    return True

def http_assembler(pcap_file):

    carved_images = 0
    faces_detected = 0

	# 打开一个 PCAP 文件
    a = rdpcap(pcap_file)

	# 利用 scapy 的高级特性自动地对 TCP 中的绘画进行分割并保存到一个字典中
    sessions = a.sessions()

    for session in sessions:
        http_payload = ""
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    # 对数据组包
					# 我们过滤了非 HTTP 的流量，然后将 HTTP 会话的负载内容拼接到一个单独的缓冲区中（类似与 wireshark 的 follow TCP stream）
                    http_payload += str(packet[TCP].payload)
            except:
                pass

		# 调用 HTTP 头分割函数，它允许我们单独处理 HTTP 头中的内容。
        headers = get_http_headers(http_payload)

        if headers is None:
            continue
		# 当我们确认在 HTTP 响应数据中包含图像内容时，我们提取图像的原始数据，返回图像类型和图像的二进制流
        image, image_type = extract_image(headers, http_payload)
        if image is not None and image_type is not None:
            # 存储图像
            file_name = "%s-pic_carver_%d.%s" % (pcap_file, carved_images, image_type)
            fd = open("%s/%s" % (pictures_directory, file_name), "wb")

            fd.write(image)
            fd.close()

            carved_images += 1

            # 开始人脸识别
            try:
                result = face_detect("%s/%s" % (pictures_directory, file_name), file_name)
                if result is True:
                    faces_detected += 1
            except:
                pass

    return carved_images, faces_detected

carved_images, faces_detected = http_assembler(pcap_file)

print("Extracted: %d images" % carved_images)
print("Detected: %d faces" % faces_detected)
