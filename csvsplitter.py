import unicodecsv

reader = list(unicodecsv.reader(open('policyrules.csv', "rb"), encoding='utf-8-sig'))
num_policies = (len(reader[0]) - 6)

for x in xrange(0,num_policies):
    filename = reader[0][5+x] +'.csv'
    print "Exporting rules into " + filename
    file = open(filename,'wb')
    header = str(reader[0][0]) + "," + str(reader[0][1]) + "," + str(reader[0][2]) +"," + str(reader[0][3]) + ",\n"
    file.writelines(header)
    for i in xrange(1,len(reader)):
        if reader[i][5+x] == "1":
            rule =  str(reader[i][0]) +"," + str(reader[i][1]) + "," + str(reader[i][2]) + ","+ str(reader[i][3] + ",\n")
            file.writelines(rule)

print "finished exporting rules into CSV-Files"