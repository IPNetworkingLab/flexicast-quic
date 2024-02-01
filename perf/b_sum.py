import sys

f=open(sys.argv[1], "r")
lines=f.readlines()
total=0
for l in lines:
    total += int(l.split(" ")[2])
start=lines[0].split(" ")
end=lines[-1].split(" ")
diff = int(end[1]) - int(start[1])
print("RESULT-BYTES ",total)
print(diff)
print("RESULT-CLIENTGP ",(total*1000000) / diff)
