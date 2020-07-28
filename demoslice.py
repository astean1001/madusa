import os
import sys
import re
import pulp
import argparse
import subprocess
import errno

import xml.etree.ElementTree as ET

sys.path.extend(['./acvtool/smiler'])

import reporter as ACV
from operator import attrgetter

TEMP_PATH = os.path.join(os.path.expanduser("~"),"demoslice","temp")

parser = argparse.ArgumentParser(description='Slicing and repackaging Android APK into demo application based on demo scenario.')
parser.add_argument('target_path', metavar='target', type=str, nargs=1,
                    help='Path to target android application.')
parser.add_argument('ec_file_path', metavar='ec_files', type=str, nargs=1,
                    help='Path to EC files.')
parser.add_argument('pickle_path', metavar='pickle', type=str, nargs=1,
                    help='Path to pickle object.')
parser.add_argument('--output', '-o', action='store',
                    help='Set output apk path')
parser.add_argument('--purge_res', action='store_true',
                    help='Purge unused resources')
parser.add_argument('--delta_debug', action='store_true',
                    help='Purge unused resources based on Delta Debugging')
parser.add_argument('--clean', action='store_true',
                    help='Clean up temporary generated files')

args = parser.parse_args()

def utf8len(s):
    return len(s.encode('utf-8'))

def unpack_target(target):
    FNULL = open(os.devnull, 'w')

    target_path_abs = os.path.abspath(target)
    unpack_process = subprocess.call("apktool d "+target_path_abs+" -o "+TEMP_PATH+" -f", shell=True, stdout=FNULL)
    
    if unpack_process != 0:
        raise Exception('Unpacking Failed : Check if apktool is installed properly.')


def get_resource_dict():
    _resource_dict = {}
    _len_resource = 0

    resource_id_xml_path = TEMP_PATH+"/res/values/public.xml"
    resource_id_tree = ET.parse(resource_id_xml_path)
    resource_id_tree_root = resource_id_tree.getroot()

    for resource_id_tree_element in resource_id_tree_root.findall('public'):
        _resource_dict[resource_id_tree_element.get("id")] = { "index": _len_resource, "type": resource_id_tree_element.get("type"), "name": resource_id_tree_element.get("name"), "size": 0, "child": [_len_resource] }
        _len_resource = _len_resource + 1

    for resource_id_tree_element in resource_id_tree_root.findall('public'):
        calculate_resource_size(_resource_dict, resource_id_tree_element.get("type"), resource_id_tree_element.get("name"))

    return _resource_dict

def get_asset_dict(resources_dict):
    _asset_dict = {}
    _len_asset = len(resources_dict)

    asset_path = TEMP_PATH + "/assets/"

    for dirpath, dirnames, filenames in os.walk(asset_path):
        try:
            _asset_dict[os.path.join(dirpath,filename)] = {"size": os.path.getsize(os.path.join(dirpath,filename)), "index": _len_asset}
            _len_asset = _len_asset + 1
        except OSError:
            raise Exception('Asset File Size Fetching Failed : Check permission settings on your home folder.')

    return _asset_dict

def build_method_dependency_graph(ec_dir, pickle, resources_dict, assets_dict):
    ec_files = [os.path.join(ec_dir, f) for f in os.listdir(ec_dir) if os.path.isfile(os.path.join(ec_dir, f))]
    smalitree = ACV.get_covered_smalitree(ec_files, pickle)

    _vertices = []
    _edges = []
    _methods = []
    _classes = []
    _chg = {}
    _len_methods = len(assets_dict) + len(resources_dict)

    for cl in smalitree.classes:
        class_name = os.path.join(cl.folder,cl.file_name)[:-6]
        dir = os.path.join(TEMP_PATH+"/smali/", cl.folder)
        if not os.path.exists(dir):
            os.makedirs(dir)

        buf = [ACV.LI_TAG(d) for d in cl.get_class_description()]
        buf.append(ACV.LI_TAG(''))
        buf.extend([ACV.LI_TAG(a) for a in cl.get_annotations()])
        buf.append(ACV.LI_TAG(''))
        buf.extend([ACV.LI_TAG(f) for f in cl.get_fields()])
        buf.append(ACV.LI_TAG(''))

        _classes = _classes + [{'name': class_name, 'buf': buf}]

        for class_desc_line in cl.get_class_description():
            if ".super" in class_desc_line:
                if class_desc_line.split(' ')[-1][:-1] in _chg.keys():
                    _chg[class_desc_line.split(' ')[-1][:-1]].append(class_name) 
                else:
                    _chg[class_desc_line.split(' ')[-1][:-1]] = [class_name]

        for m in cl.methods:
            ins_buf = []
            _cost = 0

            labels = m.labels.values()
            labels = sorted(labels, key=attrgetter('index'))

            called = m.called

            if "abstract" in m.get_method_line():
                called = True

            for i in range(len(m.insns)):
                ins = m.insns[i]
                ins_buf.append(ACV.add_tab(ins.buf))
                _cost = _cost + utf8len(ins.buf)


            count = 0
            for l in labels:
                ins_buf.insert(l.index + count, ACV.add_tab(l.buf))
                _cost = _cost + utf8len(l.buf)
                count += 1

                for t in l.tries:
                    ins_buf.insert(l.index + count, ACV.add_tab(t.buf))
                    _cost = _cost + utf8len(t.buf)
                    count += 1

                if l.switch:
                    for sl in l.switch.buf:
                        ins_buf.insert(l.index + count, ACV.add_tab(sl))
                        _cost = _cost + utf8len(sl)
                        count += 1

                if l.array_data:
                    for sl in l.array_data.buf:
                        ins_buf.insert(l.index + count, ACV.add_tab(sl))
                        _cost = _cost + utf8len(sl)
                        count += 1

            ins_buf.insert(0, ACV.LI_TAG(''))
            _cost = _cost + utf8len('')

            for a in m.annotations:
                a.reload()
                ins_buf[0:0] = [ACV.add_tab(d) for d in a.buf]
            for p in reversed(m.parameters):
                p.reload()
                ins_buf[0:0] = [ACV.add_tab(d) for d in p.buf]

            ins_buf.insert(0,ACV.add_tab(m.get_registers_line() ) )
            _cost = _cost + utf8len(m.get_registers_line())

            ins_buf.insert(0,m.get_method_line())
            ins_buf.append(ACV.LI_TAG(".end method"))
            ins_buf.append(ACV.LI_TAG(''))

            _cost = _cost + utf8len(m.get_method_line())
            _cost = _cost + utf8len(".end method")
            _cost = _cost + utf8len('')

            _methods = _methods + [{'class': class_name, 'name': m.get_desc(),'buf': ins_buf, 'size': _cost, 'res': [_len_methods]}]
            _len_methods = _len_methods + 1

            if called:
                _vertices = _vertices + [1]
            else:
                _vertices = _vertices + [0]

    searched_parent = []
    searched_child = []

    for i in range(len(_methods)):
        m = _methods[i]
        for ins in m['buf']:
            for resource_id in resources_dict.keys():
                if resource_id in ins:
                    _methods[i]['res'] = _methods[i]['res'] + resources_dict[resource_id]['child']

            for asset_name in assets_dict.keys():
                if len(asset_name.split(TEMP_PATH + "/assets/")) > 1 and asset_name.split(TEMP_PATH + "/assets/")[1] in ins:
                    _methods[i]['res'] = _methods[i]['res'] + [assets_dict[asset_name]['index']]

            is_call = re.search("^\tinvoke-", ins)
            if is_call:
                class_name = ins.split(" ")[-1].split("->")[0][1:-1]
                method_name = ins.split(" ")[-1].split("->")[1]

                target_classes = [class_name]
                search_queue = [class_name]

                while len(search_queue) > 0:
                    for _parent, _childs in _chg.items():
                        if search_queue[0] in _childs:
                            if _parent in searched_parent:
                                break
                            else:
                                if not _parent in target_classes:
                                    target_classes = target_classes + [_parent]
                                search_queue = search_queue + [_parent]
                                searched_parent = searched_parent + [_parent]
                    search_queue.pop(0)

                while len(search_queue) > 0:
                    for _parent, _childs in _chg.items():
                        if search_queue[0] == _parent:
                            for _child in _childs:
                                if _child in searched_child:
                                    break
                                else:
                                    if not _child in target_classes:
                                        target_classes = target_classes + [_child]
                                    search_queue = search_queue + [_child]
                                    searched_child = searched_child + [_child]
                    search_queue.pop(0)

                for _method in _methods:
                    if _method['class'] in target_classes and _method['name'] == method_name:
                        _edges = _edges + [(_methods.index(m), _methods.index(_method))]

    _costs = []
    _total_cost = 0
    _res_cost = 0
    _asset_cost = 0
    _method_cost = 0

    for res_key, res_elem in resources_dict.items():
        _costs = _costs + [ res_elem["size"] ]
        _total_cost = _total_cost + res_elem["size"]
        _res_cost = _res_cost + res_elem["size"]
    for asset_key, asset_elem in assets_dict.items():
        _costs = _costs + [ asset_elem["size"] ]
        _total_cost = _total_cost + asset_elem["size"]
        _asset_cost = _asset_cost + asset_elem["size"]
    for _m in _methods:
        _costs = _costs + [ _m["size"] ]
        _total_cost = _total_cost + _m["size"]
        _method_cost = _method_cost + _m["size"]

    print "Resource Cost : "+str(_res_cost)
    print "Asset Cost : "+str(_asset_cost)
    print "Method Cost : "+str(_method_cost)
    print "Total Cost : "+str(_total_cost)
    return _costs, _edges, _vertices, _methods, _classes

def solve_ilp(costs, edges, vertices, methods):
    DEMO_SIZE_LIMIT = 10000000

    model = pulp.LpProblem("Coverage_Maximizing_Problem", pulp.LpMaximize)
    x = pulp.LpVariable.dicts('x', [str(i) for i in range(len(vertices))], cat='Binary')
    r = pulp.LpVariable.dicts('r', [str(i) for i in range(len(costs))], cat='Binary')
    model += pulp.lpSum(x)
    model += pulp.lpSum([costs[v] * r[str(v)] for v in range(0,len(costs))]) <= DEMO_SIZE_LIMIT
    for v in range(0,len(vertices)):
        if vertices[v] != 1:
            model += pulp.lpSum([x[str(edge[0])] for edge in edges if edge[1] == v]) >= x[str(v)]
    for i in range(0,len(costs)):
        for v in range(len(vertices)):
            if i in methods[v]['res']:
                model += r[str(i)] - x[str(v)] >= 0
    for v in range(0,len(vertices)):
        if vertices[v] == 1:
            model += x[str(v)] == 1

    model.solve(pulp.GLPK_CMD(path='/usr/local/bin/glpsol'))

    x_val = [0]*len(vertices)
    r_val = [0]*len(costs)

    if str(pulp.LpStatus[model.status]) == "Optimal":
        for var in x:
            var_value = x[var].varValue
            x_val[int(var)] = x[var].varValue
        for var in r:
            var_value = r[var].varValue
            r_val[int(var)] = r[var].varValue
        return x_val, r_val
    else:
        return None, None

def generate_smali_code(vertices, classes, methods):
    output_dir = TEMP_PATH+"/new_smali/"
    for class_dict in classes:
        class_path = output_dir + class_dict['name'] + '.smali'
        class_buf = class_dict['buf']

        for method in methods:
            if method['class'] == class_dict['name']:
                if vertices[methods.index(method)] == 1:
                    class_buf = class_buf + method['buf']

        if len(class_buf) > 0:
            smali = "\n".join(class_buf)
            if not os.path.exists(os.path.dirname(class_path)):
                try:
                    os.makedirs(os.path.dirname(class_path))
                except OSError as exc:
                    if exc.errno != errno.EEXIST:
                        raise
            with open(class_path, 'w') as f:
                f.write(smali)

def purge_resources(resources_dict, assets_dict, resources):
    change = 0
    tempd_path = TEMP_PATH + "/temp_drawable"
    if not os.path.exists(tempd_path):
        os.makedirs(tempd_path)
    drawable_folders = subprocess.check_output(['find', TEMP_PATH+"/res", "-name", "drawable*"])
    drawable_path = ""
    for df in drawable_folders.split("\n")[:-1]:
        if df[-8:] == "drawable":
            drawable_path = df
        else:
            p = subprocess.Popen("rsync -a "+df+"/* "+tempd_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
            p.communicate()
            p2 = subprocess.Popen("rm -rf "+df, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
            p2.communicate()
        
    p = subprocess.Popen("rsync -a "+drawable_path+"/* "+tempd_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    p.communicate()
    p2 = subprocess.Popen("rm -rf "+drawable_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    p2.communicate()
    p3 = subprocess.Popen("mv "+tempd_path+" "+drawable_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    p3.communicate()
    # vsync mipmaps
    tempm_path = TEMP_PATH + "/temp_mipmap"
    if not os.path.exists(tempm_path):
        os.makedirs(tempm_path)
    mipmap_folders = subprocess.check_output(['find', TEMP_PATH+"/res", "-name", "mipmap*"])
    mipmap_path = TEMP_PATH+"/res/mipmap"
    for mf in mipmap_folders.split("\n")[:-1]:
        p = subprocess.Popen("rsync -a "+mf+"/* "+tempm_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
        p.communicate()
        p2 = subprocess.Popen("rm -rf "+mf, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
        p2.communicate()
        
    p3 = subprocess.Popen("mv "+tempm_path+" "+mipmap_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    p3.communicate()
    # purge public.xml
    public_path = TEMP_PATH + "/res/values/public.xml"
    # purge /res/values
    for dirpath, dirnames, filenames in os.walk(TEMP_PATH + "/res"):
        for filename in filenames:
            if "values" in os.path.basename(dirpath) and filename == "public.xml":
                tree = ET.parse(os.path.join(dirpath,filename))
                root = tree.getroot()
                for child in root:
                    if resources[resources_dict[child.get("id")]['index']] != 1:
                        root.remove(child)
                        change = change + 1
                if len(root) < 1:
                    os.remove(os.path.join(dirpath,filename))
                else:
                    tree.write(os.path.join(dirpath,filename), encoding='utf-8')
            elif "values" in os.path.basename(dirpath) and filename != "public.xml":
                tree = ET.parse(os.path.join(dirpath,filename))
                root = tree.getroot()
                for child in root:
                    cond_checker = False
                    if get_resource_info_by_name(resource_dict, child.tag, child.get("name"))['index'] != -1 and resources[get_resource_info_by_name(resource_dict, child.tag, child.get("name"))['index']] != 1:
                        cond_checker = True
                    if child.get("type") and get_resource_info_by_name(resource_dict, child.get("type"), child.get("name"))['index'] != -1 and resources[get_resource_info_by_name(resource_dict, child.get("type"), child.get("name"))['index']] != 1:
                        cond_checker = True
                    if cond_checker:            
                        root.remove(child)
                        change = change + 1
                if len(root) < 1:
                    os.remove(os.path.join(dirpath,filename))
                else:
                    tree.write(os.path.join(dirpath,filename), encoding='utf-8')
            else:
                fn = os.path.splitext(filename)[0].replace(".9", "")
                tag = os.path.basename(dirpath).split('-')[0]
                if get_resource_info_by_name(resource_dict, tag, fn)['index'] != -1 and resources[get_resource_info_by_name(resource_dict, tag, fn)['index']] != 1:
                    os.remove(os.path.join(dirpath,filename))
                    change = change + 1

    if os.path.exists(TEMP_PATH + "/assets"):
        for dirpath, dirnames, filenames in os.walk(TEMP_PATH + "/assets"):
            for filename in filenames:
                if resources[assets_dict[os.path.join(dirpath,filename)]['index']] != 1:
                    os.remove(os.path.join(dirpath,filename))
                    change = change + 1

    return change

def cleanup():
    p2 = subprocess.Popen("rm -rf "+TEMP_PATH, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    p2.communicate()

def repack(output_path):
    outdir = output_path
    if not outdir:
        outdir = TEMP_PATH + "/../"
    FNULL = open(os.devnull, 'w')

    repack_process = subprocess.call("apktool b "+TEMP_PATH+" -o "+outdir+"reduced_app.apk -f", shell=True, stdout=FNULL)
    
    if repack_process != 0:
        raise Exception('Unpacking Failed : Check if apktool is installed properly.')

def calculate_resource_size(resource_dict, resource_type, resource_name):
    resource_xml_path = TEMP_PATH + "/res/values/"+resource_type+"s.xml"
    resource_dir_path = TEMP_PATH + "/res/values/"+resource_type+"/"

    resource_ref = re.compile("@[a-z:/\{\}]+/[a-zA-Z0-9_.]+")
    style_ref = re.compile("\?[a-z:/\{\}]+[a-zA-Z0-9_.]+")

    target = get_resource_info_by_name(resource_dict, resource_type, resource_name)

    if len(target["child"]) > 1:
        return target["size"], target["child"]

    if os.path.exists(resource_xml_path):
        resource_value_size = 0
        resource_value_child = target["child"]
        resource_value_tree = ET.parse(resource_xml_path)
        resource_value_root = resource_value_tree.getroot()

        resource_value_search = resource_value_root.findall(".//*[@name='"+resource_name+"']")

        if len(resource_value_root.findall(".//*[@name='"+resource_name+"']")) < 1:
            pass
        else:
            for resource_value in resource_value_root.findall(".//*[@name='"+resource_name+"']"):
                for resource_attrib_val in resource_value.attrib.values():
                    if style_ref.match(resource_attrib_val):
                        resource_attrib_val = resource_attrib_val.replace("?","")
                        resource_attrib_val = resource_attrib_val.split('}')[-1]
                        if len(resource_attrib_val.split("/")) > 1:
                            style_ref_size, style_ref_child = calculate_resource_size(resource_dict, resource_attrib_val.split("/")[0], resource_attrib_val.split("/")[1])
                        else: 
                            style_ref_size, style_ref_child = calculate_resource_size(resource_dict, "style", resource_attrib_val)
                        #resource_value_size = resource_value_size + style_ref_size
                        resource_value_child = list(set(resource_value_child + style_ref_child))
                    if resource_ref.match(resource_attrib_val):
                        resource_attrib_val = resource_attrib_val.replace("@","")
                        resource_attrib_val = resource_attrib_val.split('}')[-1]
                        resource_ref_size, resource_ref_child = calculate_resource_size(resource_dict, resource_attrib_val.split('/')[0], resource_attrib_val.split('/')[1])
                        #resource_value_size = resource_value_size + resource_ref_size
                        resource_value_child = list(set(resource_value_child + resource_ref_child))

                resource_value_size = resource_value_size + utf8len(ET.tostring(resource_value))

                for resource_value_item in resource_value.iter():
                    for resource_item_attrib_val in resource_value_item.attrib.values():
                        if style_ref.match(resource_item_attrib_val):
                            resource_item_attrib_val = resource_item_attrib_val.replace("?","")
                            resource_item_attrib_val = resource_item_attrib_val.split('}')[-1]
                            if len(resource_item_attrib_val.split("/")) > 1:
                                style_ref_size, style_ref_child = calculate_resource_size(resource_dict, resource_item_attrib_val.split("/")[0], resource_item_attrib_val.split("/")[1])
                            else:
                                style_ref_size, style_ref_child = calculate_resource_size(resource_dict, "style", resource_item_attrib_val)
                            #resource_value_size = resource_value_size + style_ref_size
                            resource_value_child = list(set(resource_value_child + style_ref_child))
                        if resource_ref.match(resource_item_attrib_val):
                            resource_item_attrib_val = resource_item_attrib_val.replace("@","")
                            resource_item_attrib_val = resource_item_attrib_val.split('}')[-1]
                            resource_ref_size, resource_ref_child = calculate_resource_size(resource_dict, resource_item_attrib_val.split('/')[0], resource_item_attrib_val.split('/')[1])
                            #resource_value_size = resource_value_size + resource_ref_size
                            resource_value_child = list(set(resource_value_child + resource_ref_child))
                    resource_value_size = resource_value_size + utf8len(ET.tostring(resource_value_item))

            update_resource_size(resource_dict, resource_type, resource_name, resource_value_size)
            update_resource_child(resource_dict, resource_type, resource_name, resource_value_child)

            return resource_value_size, resource_value_child

    if os.path.exists(resource_dir_path):
        resource_file_size = 0
        for dirpath, dirnames, filenames in os.walk(resource_dir_path):
            for filename in filenames:
                if os.path.splitext(filename)[0] == resource_name:
                    try:
                        resource_file_size = resource_file_size + os.path.getsize(os.path.join(dirpath,filename))
                    except OSError:
                        raise Exception('Resource File Size Fetching Failed : Check permission settings on your home folder.')

                    if os.path.splitext(filename)[1] == ".xml":
                        with open(os.path.join(dirpath,filename), "r") as resource_xml_file:
                            resource_xml_file_lines = f.readlines()
                            for resource_xml_file_line in resource_xml_file_lines:
                                resource_ref_list = resource_ref.findall(resource_xml_file_line)
                                style_ref_list = style_ref.findall(resource_xml_file_line)

                                for resource_ref_element in resource_ref_list:
                                    resource_ref_element_stripns = resource_ref_element.replace("@","")
                                    resource_ref_element_stripns = resource_ref_element_stripns.split('}')[-1]
                                    resource_ref_size, resource_ref_child = calculate_resource_size(resource_dict, resource_ref_element_stripns.split('/')[0], resource_ref_element_stripns.split('/')[1])
                                    resource_file_size = resource_file_size + resource_ref_size
                                    resource_value_child = list(set(resource_value_child + resource_ref_child))

                                for style_ref_element in style_ref_list:
                                    style_ref_element_stripns = style_ref_element.replace("?","")
                                    style_ref_element_stripns = style_ref_element_stripns.split('}')[-1]
                                    if len(style_ref_element_stripns.split("/")) > 1:
                                        style_ref_size, style_ref_child = calculate_resource_size(resource_dict, style_ref_element_stripns.split("/")[0], style_ref_element_stripns.split("/")[1])
                                    else:
                                        style_ref_size, style_ref_child = calculate_resource_size(resource_dict, "style", style_ref_element_stripns)
                                    resource_file_size = resource_file_size + style_ref_size
                                    resource_value_child = list(set(resource_value_child + style_ref_child))
                    
                    update_resource_size(resource_dict, resource_type, resource_name, resource_file_size)
                    update_resource_child(resource_dict, resource_type, resource_name, resource_value_child)

                    return resource_value_size, resource_value_child

    return target["size"], target["child"]

def update_resource_size(resource_dict, resource_type, resource_name, update_size):
    for key, val in resource_dict.items():
        if val["type"] == resource_type and val["name"] == resource_name:
            resource_dict[key]["size"] = resource_dict[key]["size"] + update_size

def update_resource_child(resource_dict, resource_type, resource_name, update_child):
    for key, val in resource_dict.items():
        if val["type"] == resource_type and val["name"] == resource_name:
            resource_dict[key]["child"] = update_child

def get_resource_info_by_name(resource_dict, resource_type, resource_name):
    for key, val in resource_dict.items():
        if val["type"] == resource_type and val["name"] == resource_name:
            return resource_dict[key]
    return {"type":"", "name":"", "size":0, "index":-1, "child": []}

print "Welcome to Instant-slicer!"
print "Unpacking target application at : "+TEMP_PATH
unpack_target(args.target_path[0])
print "Parsing resource list from XML ..."
resource_dict = get_resource_dict()
print "Parsing asset list from directory ..."
asset_dict = get_asset_dict(resource_dict)
print "Calculating resource size weighted method dependency graph ..."
costs, edges, vertices, methods, classes = build_method_dependency_graph(args.ec_file_path[0], args.pickle_path[0], resource_dict, asset_dict)
edges = list(set(edges))
print "Solving Maximum Code Coverage Problem ..."
vertices, resources = solve_ilp(costs, edges, vertices, methods)
'''
res_name = []
for res_key, res_elem in resource_dict.items():
    res_name = res_name + [ res_elem["type"] + "/" + res_elem["name"] ]
for asset_key, asset_elem in asset_dict.items():
    res_name = res_name + [ "assets/"+asset_key ]
for _m in methods:
    res_name = res_name + [ _m["class"]+"/"+_m["name"] ]
for r in range(len(resources)):
    if resources[r] == None:
        sys.stdout.write(res_name[r] + ", ")
        sys.stdout.flush()
'''
print "Generating Smali Code based on ILP results ..."
generate_smali_code(vertices, classes, methods)

if args.purge_res:
    print "Deleting Unused Resources ..."
    change = 1
    while change:
        change = purge_resources(resource_dict, asset_dict, resources)
        print str(change) + " resources deleted."

print "Repackaging into APK ..."
repack(args.output)

if args.clean:
    print "Cleaning up all the mess ..."
    cleanup()

print "Done!"

