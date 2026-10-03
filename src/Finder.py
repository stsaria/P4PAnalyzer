#!/usr/bin/env python3
"""
P4P5 高速トラフィック・ヒートマップ

実行:
    sudo -E python3 p4p5_heatmap.py            # 実トラフィック (rawソケットは root/管理者権限が必要)
    python3 p4p5_heatmap.py --demo 5000        # 5000ノードの疑似トラフィックで動作確認

依存: pip install pygame numpy
操作: ESC で終了 / ノードにマウスを乗せると IP:Port 表示
"""
import argparse
import math
import random
import socket
import sys
import threading
import time
from collections import deque

import numpy as np
import pygame

MAGIC = b"P4P5"
DEFAULT_PORT = 15987
LEFT_W = 360
PAD = 10
BG = (10, 12, 16)
EMPTY = (16, 18, 24)
BASE = np.array([30, 45, 75], np.float32)       # 通信のないノード
SRC_COL = np.array([0, 225, 110], np.float32)   # 送信元フラッシュ(緑)
DST_COL = np.array([225, 140, 0], np.float32)   # 宛先フラッシュ(橙)
DECAY_PER_SEC = 1.8                              # フラッシュが消える速さ

# スニファ → GUI の受け渡し。deque の append/popleft はスレッドセーフ。
# maxlen を付けて、GUIが追い付かない場合は古いものから捨てる(メモリ暴走防止)
packetQueue = deque(maxlen=1_000_000)
sniffStatus = {"mode": "starting"}


# ---------------------------------------------------------------- 受信側
def keyToStr(k: bytes) -> str:
    return f"{k[0]}.{k[1]}.{k[2]}.{k[3]}:{int.from_bytes(k[4:6], 'big')}"


def openSocket(port):
    try:
        if sys.platform == "win32":
            host = socket.gethostbyname(socket.gethostname())
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((host, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            s.bind(("0.0.0.0", 0))
        mode = "raw"
    except Exception:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("0.0.0.0", port))
        mode = "udp"
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 << 20)  # 取りこぼし防止
    except OSError:
        pass
    return s, mode


def sniffLoop(port):
    try:
        s, mode = openSocket(port)
    except Exception as e:
        sniffStatus["mode"] = f"socket error: {e}"
        return
    sniffStatus["mode"] = mode

    buf = bytearray(65535)
    mv = memoryview(buf)
    append = packetQueue.append

    if mode == "raw":
        # ノードキーは「IP4バイト + Port2バイト」の6バイト bytes。文字列化はGUI側で必要時のみ。
        while True:
            try:
                n = s.recv_into(buf)
            except OSError:
                break
            if n < 28 or buf[9] != 17:          # UDP以外は捨てる
                continue
            ihl = (buf[0] & 0x0F) << 2
            if buf[ihl + 8:ihl + 12] != MAGIC:
                continue
            append((bytes(mv[12:16]) + bytes(mv[ihl:ihl + 2]),
                    bytes(mv[16:20]) + bytes(mv[ihl + 2:ihl + 4]),
                    n - ihl - 8))
    else:
        localDst = bytes(4) + port.to_bytes(2, "big")
        while True:
            try:
                n, addr = s.recvfrom_into(buf)
            except OSError:
                break
            if buf[:4] != MAGIC:
                continue
            append((socket.inet_aton(addr[0]) + addr[1].to_bytes(2, "big"), localDst, n))


def demoLoop(nodes, rate):
    sniffStatus["mode"] = "demo"
    rnd = random.Random()
    keys = [bytes([192, 168, rnd.randrange(256), rnd.randrange(1, 255)]) + (10000 + i).to_bytes(2, "big")
            for i in range(nodes)]
    dst = bytes([192, 168, 0, 1]) + DEFAULT_PORT.to_bytes(2, "big")
    batch = max(1, rate // 200)
    choice = rnd.choice
    while True:
        for _ in range(batch):
            packetQueue.append((choice(keys), dst if rnd.random() < 0.7 else choice(keys), 120))
        time.sleep(0.005)


# ---------------------------------------------------------------- 描画側
class Viz:
    def __init__(self):
        pygame.init()
        self.screen = pygame.display.set_mode((1280, 720), pygame.RESIZABLE)
        pygame.display.set_caption("P4P5 Traffic Heatmap")
        self.clock = pygame.time.Clock()
        self.font = pygame.font.SysFont("monospace", 14)
        self.uiFont = pygame.font.SysFont("sans-serif", 18)

        self.keys = []
        self.index = {}
        self.cap = 1024
        self.heatS = np.zeros(self.cap, np.float32)
        self.heatD = np.zeros(self.cap, np.float32)
        self.counts = np.zeros(self.cap, np.int64)

        self.bufTotal = 0
        self.rgbF = None
        self.u8 = None
        self.layout = None

        self.totalPk = 0
        self.winPk = 0
        self.winBytes = 0
        self.winStart = time.perf_counter()
        self.pps = 0.0
        self.bps = 0.0
        self.history = deque([0.0] * 120, maxlen=120)
        self.textSurfs = []

    # ノード登録（配列は倍々で拡張）
    def register(self, key):
        i = len(self.keys)
        self.keys.append(key)
        self.index[key] = i
        if i >= self.cap:
            newCap = self.cap * 2
            for name in ("heatS", "heatD", "counts"):
                old = getattr(self, name)
                new = np.zeros(newCap, old.dtype)
                new[:self.cap] = old
                setattr(self, name, new)
            self.cap = newCap
        return i

    def decay(self, dt):
        n = len(self.keys)
        if not n:
            return
        d = np.float32(dt * DECAY_PER_SEC)
        for h in (self.heatS[:n], self.heatD[:n]):
            np.subtract(h, d, out=h)       # 線形減衰（指数減衰だと非正規化数で遅くなるため）
            np.maximum(h, 0, out=h)

    # キューをまとめて処理（時間予算つき：溜まってもUIは止まらない）
    def drain(self, budget=0.008):
        index = self.index
        pop = packetQueue.popleft
        sl, dl = [], []
        nb = 0
        t0 = time.perf_counter()
        try:
            while True:
                for _ in range(1024):
                    s, d, sz = pop()
                    a = index.get(s)
                    if a is None:
                        a = self.register(s)
                    b = index.get(d)
                    if b is None:
                        b = self.register(d)
                    sl.append(a)
                    dl.append(b)
                    nb += sz
                if time.perf_counter() - t0 > budget:
                    break
        except IndexError:
            pass

        if sl:
            sa = np.array(sl, np.int64)
            self.heatS[sa] = 1.0
            self.heatD[np.array(dl, np.int64)] = 1.0
            n = len(self.keys)
            self.counts[:n] += np.bincount(sa, minlength=n)
            self.totalPk += len(sl)
            self.winPk += len(sl)
            self.winBytes += nb

        now = time.perf_counter()
        if now - self.winStart >= 0.25:
            dt = now - self.winStart
            self.pps = self.winPk / dt
            self.bps = self.winBytes / dt
            self.history.append(self.pps)
            self.winPk = self.winBytes = 0
            self.winStart = now
            self.rebuildText()

    # テキストは 0.25 秒に1回だけ描画し、毎フレームは blit のみ
    def rebuildText(self):
        n = len(self.keys)
        lines = [
            f"Nodes   : {n:,}",
            f"Packets : {self.totalPk:,}",
            f"Rate    : {self.pps:,.0f} pkt/s",
            f"Traffic : {self.bps / 1e6:.2f} MB/s",
            f"Backlog : {len(packetQueue):,}",
            f"FPS     : {self.clock.get_fps():.0f}",
            f"Socket  : {sniffStatus['mode']}",
            "",
            "Top senders:",
        ]
        if n:
            k = min(14, n)
            c = self.counts[:n]
            top = np.argpartition(c, -k)[-k:]
            top = top[np.argsort(c[top])[::-1]]
            for i in top:
                if c[i] > 0:
                    lines.append(f"{keyToStr(self.keys[i]):<22}{int(c[i]):>9,}")
        self.textSurfs = [self.font.render(t, True, (210, 225, 235)) for t in lines]

    def drawGrid(self, W, H):
        n = len(self.keys)
        areaW, areaH = W - LEFT_W - 2 * PAD, H - 2 * PAD
        self.layout = None
        if n == 0 or areaW < 10 or areaH < 10:
            return

        # 容量(2のべき乗)基準でレイアウト → ノード追加のたびに配置が動かない
        cap = max(256, 1 << (n - 1).bit_length())
        cols = max(1, math.ceil(math.sqrt(cap * areaW / areaH)))
        rows = math.ceil(cap / cols)
        total = cols * rows
        if total != self.bufTotal:
            self.bufTotal = total
            self.rgbF = np.zeros((total, 3), np.float32)
            self.u8 = np.empty((total, 3), np.uint8)
            self.u8[:] = EMPTY

        # 色計算は numpy で一括（ノード数に関わらず Python ループなし）
        rgb = self.rgbF[:n]
        rgb[:] = BASE
        rgb += self.heatS[:n, None] * SRC_COL
        rgb += self.heatD[:n, None] * DST_COL
        np.minimum(rgb, 255, out=rgb)
        self.u8[:n] = rgb

        img = self.u8.reshape(rows, cols, 3)
        small = pygame.image.frombuffer(img.data, (cols, rows), "RGB")

        cell = min(areaW / cols, areaH / rows)
        if cell >= 1:
            cell = min(int(cell), 48)
            tw, th = cols * cell, rows * cell
        else:                                   # 画素数より多いときは間引き表示
            tw, th = areaW, areaH
        big = pygame.transform.scale(small, (tw, th))   # 最近傍拡大＝最速
        ox = LEFT_W + PAD + (areaW - tw) // 2
        oy = PAD + (areaH - th) // 2
        self.screen.blit(big, (ox, oy))

        if cell >= 6:                           # セルが大きい時だけ格子線
            for c in range(1, cols):
                x = ox + c * cell
                pygame.draw.line(self.screen, BG, (x, oy), (x, oy + th - 1))
            for r in range(1, rows):
                y = oy + r * cell
                pygame.draw.line(self.screen, BG, (ox, y), (ox + tw - 1, y))

        self.layout = (ox, oy, tw, th, cols, rows)

    def drawHover(self):
        if not self.layout:
            return
        ox, oy, tw, th, cols, rows = self.layout
        mx, my = pygame.mouse.get_pos()
        if 0 <= mx - ox < tw and 0 <= my - oy < th:
            c = int((mx - ox) * cols / tw)
            r = int((my - oy) * rows / th)
            i = r * cols + c
            if i < len(self.keys):
                t = self.font.render(f"#{i} {keyToStr(self.keys[i])}  sent:{int(self.counts[i]):,}",
                                     True, (255, 255, 255))
                pygame.draw.rect(self.screen, (30, 40, 50), (mx + 15, my, t.get_width() + 10, 22))
                self.screen.blit(t, (mx + 20, my + 3))

    def drawPanel(self, H):
        pygame.draw.rect(self.screen, (20, 22, 28), (0, 0, LEFT_W, H))
        pygame.draw.line(self.screen, (40, 43, 55), (LEFT_W, 0), (LEFT_W, H), 2)
        self.screen.blit(self.uiFont.render("P4P5 Traffic Heatmap", True, (0, 255, 200)), (24, 18))

        # 受信レートのスパークライン
        x0, y0, w, h = 24, 52, LEFT_W - 48, 50
        pygame.draw.rect(self.screen, (14, 16, 20), (x0, y0, w, h))
        peak = max(max(self.history), 1.0)
        m = len(self.history)
        pts = [(x0 + i * w / (m - 1), y0 + h - 2 - (v / peak) * (h - 4)) for i, v in enumerate(self.history)]
        pygame.draw.lines(self.screen, (0, 200, 160), False, pts, 1)

        y = y0 + h + 14
        for s in self.textSurfs:
            self.screen.blit(s, (24, y))
            y += 19

    def run(self):
        last = time.perf_counter()
        while True:
            for e in pygame.event.get():
                if e.type == pygame.QUIT or (e.type == pygame.KEYDOWN and e.key == pygame.K_ESCAPE):
                    pygame.quit()
                    return
            now = time.perf_counter()
            dt = min(now - last, 0.1)
            last = now

            self.decay(dt)
            self.drain()

            W, H = self.screen.get_size()
            self.screen.fill(BG)
            self.drawGrid(W, H)
            self.drawPanel(H)
            self.drawHover()
            pygame.display.flip()
            self.clock.tick(60)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--demo", type=int, default=0, metavar="NODES", help="疑似トラフィックで起動")
    ap.add_argument("--demo-rate", type=int, default=50000, help="疑似パケット/秒")
    args = ap.parse_args()

    if args.demo:
        threading.Thread(target=demoLoop, args=(args.demo, args.demo_rate), daemon=True).start()
    else:
        threading.Thread(target=sniffLoop, args=(args.port,), daemon=True).start()

    try:
        Viz().run()
    except KeyboardInterrupt:
        pygame.quit()


if __name__ == "__main__":
    main()