import os
import sys
import re
import pulp
import argparse

import xml.etree.ElementTree as ET

sys.path.extend(['./acvtool/smiler'])

import reporter as ACV

TEMP_PATH = '~/demoslice/temp'

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

unpack_target(args.target_path[0])
resource_dict = get_resource_dict()
asset_dict = get_asset_dict()
costs, edges, vertices, methods, classes = build_method_dependency_graph(args.ec_file_path[0], args.pickle_path[0], resource_dict, asset_dict)
vertices = solve_ilp(costs, edges, vertices)
generate_smali_code(vertices, classes, methods, args.output)

def utf8len(s):
    return len(s.encode('utf-8'))

def unpack_target(target):
    target_path_abs = os.path.abspath(target)
    unpack_process = subprocess.call("apktool d "+target_path_abs+" -o "+TEMP_PATH, shell=True)
    
    if unpack_process != 0:
        raise Exception('Unpacking Failed : Check if apktool is installed properly.') 


def get_resource_dict():
    _resource_dict = {}

    resource_id_xml_path = TEMP_PATH + "res/values/public.xml"
    resource_id_tree = ET.parse(resource_id_xml_path)
    resource_id_tree_root = resource_id_tree.getroot()

    for resource_id_tree_element in resource_id_tree_root.findall('public'):
        _resource_dict[child.get("id")] = { "type": resource_id_tree_element.get("type"), "name": resource_id_tree_element.get("name"), "size": 0 }

    for resource_id_tree_element in resource_id_tree_root.findall('public'):
        calculate_resource_size(_resource_dict, resource_id_tree_element.get("type"), resource_id_tree_element.get("name"))

    return _resource_dict

def get_asset_dict():
    _asset_dict = {}
    asset_path = TEMP_PATH + "/assets/"

    for dirpath, dirnames, filenames in os.walk(asset_path):
        try:
            _asset_dict[os.path.join(dirpath,filename)] = os.path.getsize(os.path.join(dirpath,filename))
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
    _costs = []
    _chg = {}

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

        _classes = _classes + {'name': class_name, 'buf': buf}

        for class_desc_line in cl.get_class_description():
            if ".super" in class_desc_line:
                if class_desc_line.split(' ')[-1][:-1] in _chg.keys():
                    _chg[class_desc_line.split(' ')[-1][:-1]].append(class_name) 
                else:
                    _chg[class_desc_line.split(' ')[-1][:-1]] = [class_name]

        for m in cl.methods:
            ins_buf = []
            _cost = 0

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

            _methods = _methods + [{'class': class_name, 'name': m.get_desc(),'buf': ins_buf}]
            _costs = _costs + [_cost]

            if called:
                _vertices = _vertices + [1]
            else:
                _vertices = _vertices + [0]

    for m in _methods:
        for ins in _methods['buf']:
            for resource_id in resources_dict.keys():
                if resource_id in ins:
                    _costs[_methods.index(m)] = _costs[_methods.index(m)] + resources_dict[resource_id]['size']

            for asset_name in assets_dict.keys():
                if len(asset_name.split(TEMP_PATH + "/assets/")) > 1 and asset_name.split(TEMP_PATH + "/assets/")[1] in ins:
                    _costs[_methods.index(m)] = _costs[_methods.index(m)] + assets_dict[asset_name]

            is_call = re.search("^invoke-", ins)
            if is_call:
                class_name = ins.split(" ")[-1].split("->")[0][1:-1]
                method_name = ins.split(" ")[-1].split("->")[1]

                target_classes = [class_name]
                search_queue = [class_name]

                while len(search_queue) > 0:
                    for _parent, _childs in _chg.items():
                        if search_queue[0] in _childs:
                            target_classes = target_classes + [_parent]
                            search_queue.extend(_childs)
                    search_queue.pop(0)
                return search_queue

                while len(search_queue) > 0:
                    for _parent, _childs in _chg.items():
                        if search_queue[0] == _parent:
                            target_classes.extend(_childs)
                            search_queue.extend(_child)
                    search_queue.pop(0)
                return search_queue

                for _method in _methods:
                    if _method['class'] in target_classes and _method['name'] == method_name:
                        _edges = _edges + [(_methods.index(m), _methods.index(_method))]
    return _costs, _edges, _vertices, _methods, _classes

def solve_ilp(costs, edges, vertices):
    DEMO_SIZE_LIMIT = 10000000

    x = [0]*len(vertices)

    print x

    model = pulp.LpProblem("Coverage Maximizing Problem", pulp.LpMaximize)
    model += pulp.lpSum(x)
    model += pulp.lpSum([costs[v] * x[v] for v in range(0,len(vertices))]) <= DEMO_SIZE_LIMIT
    for v in range(0,len(vertices)):
        model += pulp.lpSum([x[edge[0]] for edge in edges if edge[1] == v]) - x[v] >= 0
    for v in range(0,len(vertices)):
        if vertices[v] == 1:
            model += x[v] == 1

    model.solve()

    print pulp.LpStatus[model.status]
    print x

    return x

def generate_smali_code(vertices, classes, methods, output_dir):
    for class_dict in classes:
        class_path = os.path.join(output_dir, class_dict['name'] + '.smali')
        class_buf = class_dict['buf']

        for method in methods:
            if method['class'] == class_dict['name']:
                if vertices[methods.index(method)] == 1:
                    class_buf = class_buf + method['buf']

        if len(class_buf) > 0:
            smali = "\n".join(class_buf)
            with open(class_path, 'w') as f:
                f.write(smali)

def cleanup():
    pass

def calculate_resource_size(resource_dict, resource_type, resource_name):
    resource_xml_path = TEMP_PATH + "res/values/"+resource_type+"s.xml"
    resource_dir_path = TEMP_PATH + "res/values/"+resource_type+"/"

    resource_ref = re.compile("@[a-z]+/[a-zA-Z_]+")
    style_ref = re.compile("?[a-zA-Z_]+")

    if get_resource_size_by_name(resource_dict, resource_type, resource_name) != 0:
        return get_resource_size_by_name(resource_dict, resource_type, resource_name)

    if os.path.exists(resource_xml_path):
        resource_value_size = 0
        resource_value_tree = ET.parse(resource_xml_path)
        resource_value_root = resource_id_tree.getroot()

        resource_value_search = resource_value_root.findall("[@name="+resource_name+"]")

        if len(resource_value_root.findall("[@name="+resource_name+"]")) < 1:
            pass
        else:
            for resource_value in resource_value_root.findall("[@name="+resource_name+"]"):
                for resource_attrib_val in resource_value.attrib.values():
                    if style_ref.match(resource_attrib_val):
                        style_ref_size = calculate_resource_size(resource_dict, "style", resource_attrib_val[1:])
                        resource_value_size = resource_value_size + style_ref_size
                    if resource_ref.match(resource_attrib_val):
                        resource_ref_size = calculate_resource_size(resource_dict, resource_attrib_val.split('/')[0][1:], resource_attrib_val.split('/')[1])
                        resource_value_size = resource_value_size + resource_ref_size

                resource_value_size = resource_value_size + utf8len(ET.tostring(resource_value))

                for resource_value_item in resource_value.iter():
                    for resource_item_attrib_val in resource_value_item.attrib.values():
                        if style_ref.match(resource_item_attrib_val):
                            style_ref_size = calculate_resource_size(resource_dict, "style", resource_item_attrib_val[1:])
                            resource_value_size = resource_value_size + style_ref_size
                        if resource_ref.match(resource_item_attrib_val):
                            resource_ref_size = calculate_resource_size(resource_dict, resource_item_attrib_val.split('/')[0][1:], resource_item_attrib_val.split('/')[1])
                            resource_value_size = resource_value_size + resource_ref_size
                    resource_value_size = resource_value_size + utf8len(ET.tostring(resource_value_item))

            update_resource_size(resource_dict, resource_type, resource_name, resource_value_size)

            return resource_value_size

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
                                    resource_ref_size = calculate_resource_size(resource_dict, resource_ref_element.split('/')[0][1:], resource_ref_element.split('/')[1])
                                    resource_file_size = resource_file_size + resource_ref_size

                                for style_ref_element in style_ref_list:
                                    style_ref_size = calculate_resource_size(resource_dict, "style", style_ref_element[1:])
                                    resource_file_size = resource_file_size + style_ref_size
                    
                    update_resource_size(resource_dict, resource_type, resource_name, resource_file_size)

                    return resource_file_size

    return get_resource_size_by_name(resource_dict, resource_type, resource_name)

def update_resource_size(resource_dict, resource_type, resource_name, update_size):
    for key, val in resource_dict.items():
        if val["type"] == resource_type and val["name"] == resource_name:
            resource_dict[key]["size"] = resource_dict[key]["size"] + update_size

def  get_resource_size_by_name(resource_dict, resource_type, resource_name):
    for key, val in resource_dict.items():
        if val["type"] == resource_type and val["name"] == resource_name:
            return resource_dict[key]["size"]
    return 0