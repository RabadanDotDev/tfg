import json

with open('tmp/packet_pincer_botiot_labels_count.json') as f:
    botiot = json.loads(f.read())

with open('tmp/packet_pincer_toniot_labels_count.json') as f:
    toniot = json.loads(f.read())

with open('tmp/packet_pincer_cicddos_labels_count.json') as f:
    cicddos = json.loads(f.read())

print("-------------------------------------------------------------")
print("botiot")
botiot_sum = sum([v for _,v in botiot.items()])
for k in sorted(botiot.keys()):
    print(k, f"{botiot[k]} ({round(botiot[k]/botiot_sum*100, 3)}\\%)")

print("-------------------------------------------------------------")
print("toniot")
toniot_sum = sum([v for _,v in toniot.items()])
for k in sorted(toniot.keys()):
    print(k, f"{toniot[k]} ({round(toniot[k]/toniot_sum*100, 3)}\\%)")

print("-------------------------------------------------------------")
print("cicddos")
cicddos_sum = sum([v for _,v in cicddos.items()])
for k in sorted(cicddos.keys()):
    print(k, f"{cicddos[k]} ({round(cicddos[k]/cicddos_sum*100, 3)}\\%)")

combined={}
for k in botiot:
    if k in combined:
        combined[k] += botiot[k]
    else:
        combined[k] = botiot[k]

for k in cicddos:
    if k in combined:
        combined[k] += cicddos[k]
    else:
        combined[k] = cicddos[k]

for k in toniot:
    if k in combined:
        combined[k] += toniot[k]
    else:
        combined[k] = toniot[k]

print("-------------------------------------------------------------")
print("combined")
combined_sum = sum([v for _,v in combined.items()])
for k in  sorted(combined.keys()):
    print(k, f"{combined[k]} ({round(combined[k]/combined_sum*100, 3)}\\%)")
