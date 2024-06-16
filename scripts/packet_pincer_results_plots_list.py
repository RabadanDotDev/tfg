import json

# Load jsons
with open('/workspaces/tfg/tmp/packet_pincer_cicddos_labels_count.json') as f:
    cicddos_unsorted: dict = json.loads(f.read())
with open('/workspaces/tfg/tmp/packet_pincer_botiot_labels_count.json') as f:
    botiot_unsorted: dict = json.loads(f.read())
with open('/workspaces/tfg/tmp/packet_pincer_toniot_labels_count.json') as f:
    toniot_unsorted: dict = json.loads(f.read())

# Get all labels
labels = set(botiot_unsorted.keys()) | set(toniot_unsorted.keys()) | set(cicddos_unsorted.keys())

# Create dictionaries
cicddos={"benign": 0};  cicddos_sum  = 0
botiot={"benign": 0};   botiot_sum   = 0
toniot={"benign": 0};   toniot_sum   = 0
combined={"benign": 0}; combined_sum = 0
for label in sorted(list(labels)):
    cicddos[label]  = cicddos_unsorted[label] if label in cicddos_unsorted else 0
    botiot[label]   = botiot_unsorted[label]  if label in botiot_unsorted  else 0
    toniot[label]   = toniot_unsorted[label]  if label in toniot_unsorted  else 0
    combined[label] = cicddos[label] + botiot[label] + toniot[label]

    cicddos_sum  += cicddos[label]
    botiot_sum   += botiot[label]
    toniot_sum   += toniot[label]
    combined_sum += combined[label]

# Write latex table
with open("/workspaces/tfg/report/practical_framework/ml_with_tool_assigned_tags_table.tex", 'w') as f:
    f.write("\\begin{table}[H]\n")
    f.write("    \\resizebox{\\textwidth}{!}{%\n")
    f.write("        \\begin{tabular}{|c | r r r | c |}\n")
    f.write("            \\hline\n")
    f.write("            \\textbf{Etiqueta}               & \\textbf{CIC-DDoS2019}            & \\textbf{Bot-IoT}            & \\textbf{TON-IoT}            &        \\textbf{Total} \\\\  \hline\n")

    for k in combined.keys():
        # Write key
        f.write(k.replace('_', '\\_'))
        f.write(' & ')

        # Write cic
        f.write('{:,}'.format(cicddos[k]).replace(',', ' '))
        f.write(' (')
        f.write("{:5.3f}".format(cicddos[k]/cicddos_sum*100))
        f.write("\\%) & ")

        # Write botiot
        f.write('{:,}'.format(botiot[k]).replace(',', ' '))
        f.write(' (')
        f.write("{:5.3f}".format(botiot[k]/botiot_sum*100))
        f.write("\\%) & ")

        # Write toniot
        f.write('{:,}'.format(toniot[k]).replace(',', ' '))
        f.write(' (')
        f.write("{:5.3f}".format(toniot[k]/toniot_sum*100))
        f.write("\\%) & ")
        
        # Write comibined
        f.write('{:,}'.format(combined[k]).replace(',', ' '))
        f.write(' (')
        f.write("{:5.3f}".format(combined[k]/combined_sum*100))
        f.write("\\%) \\\\\n")
        
    f.write("            \\hline\n")
    f.write("        \\end{tabular}\n")
    f.write("    }\n")
    f.write("    \\caption{Etiquetas asignadas por cada conjunto de datos}\n")
    f.write("    \\label{table:packetpincerassignedlabels}\n")
    f.write("\\end{table}\n")
