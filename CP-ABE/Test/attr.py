from Crypto.Util.number import bytes_to_long,long_to_bytes
import json

if __name__ == '__main__':
    filename = "phr5.json"
    sourcefile = open(filename, 'rb')
    msg = sourcefile.read()
    sourcefile.close()
    msg_dict = json.loads(msg)
    attr_list = [msg_dict['ID']]
    policy = '((' + msg_dict["ID"] + ') or (' 
    for item in msg_dict['NGUOIPHUTRACH']:
        attr_list.append(item['ID'])
        attr_list.append(item['khoa'].upper())
        if msg_dict['NGUOIPHUTRACH'][-1] != item:
            policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + " or "
        else:
            policy += "(" + item['ID'] + ' and ' + item['khoa'].upper() + ")" + '))'

    print(policy)
    print(attr_list)
    #attr_list = [msg_dict["ID"]]

    # convert attr_list to a JSON string
    attr_list_json = json.dumps(attr_list)

    # write JSON string to file
    with open("attr5.txt", "w") as sourcefile:
        sourcefile.write(attr_list_json)
