import os
import sys
import cgi
import re
import time
import pulp
import argparse
import javaobj
import shutil
import logging
import random
import subprocess
import errno

from tqdm import tqdm
import cPickle as pickle

import xml.etree.ElementTree as ET


from smiler.instrumenting.apkil.smalitree import SmaliTree
from operator import attrgetter

dupchecker = int(random.random() * 10000000000)

TEMP_PATH = os.path.join(os.path.expanduser("~"),"demoslice","temp_"+str(dupchecker))
TEMP_PATH_BACKUP = os.path.join(os.path.expanduser("~"),"demoslice","temp_orig_"+str(dupchecker))
TEMP_PATH_ILP = os.path.join(os.path.expanduser("~"),"demoslice")


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
parser.add_argument('--merge', action='store_true',
                    help='Merge drawables/mipmaps into medium resolution')
parser.add_argument('--percent', '-p', action='store', type=float,
                    help='Set APK size limit in percent')
parser.add_argument('--byte', '-b', action='store', type=int,
                    help='Set APK size limit in byte')
parser.add_argument('--clean', action='store_true',
                    help='Clean up temporary generated files')

args = parser.parse_args()

DEMO_SIZE_SUCCESS_MINIMUM = 0                   # APK Minimum Size successfully Generated
DEMO_SIZE_LIMIT = 10000000                      # Current ILP Size Constraint
DEMO_SIZE_LIMIT_SUCCESS = 0
DEMO_SIZE_LIMIT_L = 0                           # Lower Limit of Binary Search
DEMO_SIZE_LIMIT_R = 20000000                    # Upper Limit of Binary Search < Unpacked Android App Size
APK_SIZE_LIMIT = 10000000                       # Actual APK Size Limit == 10MB
SEARCH_DEPTH = 5                                # Binary Search Limit

def utf8len(s):
    return len(s.encode('utf-8'))

def get_covered_smalitree(ec_files, pickle_path):
    st = None
    with open(pickle_path, 'rb') as f:
        st = pickle.load(f)
    for ec in ec_files:
        coverage = read_ec(ec)
        cover_smalitree(st, coverage)
    return st

def LI_TAG(str):
    return '%s' % str

def add_tab(txt):
    return "\t{}".format(txt)

def read_ec(ec_path):
    pobj = ''
    with open(ec_path, mode='rb') as f:
        marshaller = javaobj.JavaObjectUnmarshaller(f)
        pobj = marshaller.readObject()
    return pobj

def cover_smalitree(st, coverage):
    i = 0
    for c_i in range(len(st.classes)):
        cl = st.classes[c_i]
        if cl.is_coverable():
            cov_class = coverage[i]
            i += 1
            for m_i in range(len(cl.methods)):
                method = cl.methods[m_i]
                method.called = method.cover_code > -1 and cov_class[method.cover_code]
                for ins in method.insns:
                    ins.covered = ins.cover_code > -1 and cov_class[ins.cover_code]
                for k, lbl in method.labels.items():
                    lbl.covered = lbl.cover_code > -1 and cov_class[lbl.cover_code]

def resetToOriginal():
    FNULL = open(os.devnull, 'w')
    delete_temp_process = subprocess.call("rm -rf "+TEMP_PATH, shell=True, stdout=FNULL)
    copy_backup_process = subprocess.call("cp -r "+TEMP_PATH_BACKUP+" "+TEMP_PATH, shell=True, stdout=FNULL)

def get_original_apk_size(target):
    target_path_abs = os.path.abspath(target)
    return os.path.getsize(target_path_abs)
    

def unpack_target(target):
    FNULL = open(os.devnull, 'w')

    target_path_abs = os.path.abspath(target)
    unpack_process = subprocess.call("apktool d "+target_path_abs+" -o "+TEMP_PATH+" -f", shell=True, stdout=FNULL)
    unpack_process_backup = subprocess.call("cp -r "+TEMP_PATH+" "+TEMP_PATH_BACKUP, shell=True, stdout=FNULL)
    
    if unpack_process != 0:
        raise Exception('Unpacking Failed : Check if apktool is installed properly.')

    total_size = 0
    for path, dirs, files in os.walk(TEMP_PATH):
        for f in files:
            fp = os.path.join(path, f)
            total_size += os.path.getsize(fp)

    return total_size

# Parsing public.xml and make resource dictionary, which uses resource id as key
def get_resource_dict():
    _resource_dict = {}
    _resource_idx_by_name = {}
    _len_resource = 0

    resource_id_xml_path = TEMP_PATH+"/res/values/public.xml"
    resource_id_tree = ET.parse(resource_id_xml_path)
    resource_id_tree_root = resource_id_tree.getroot()

    for resource_id_tree_element in resource_id_tree_root.findall('public'):
        _resource_dict[resource_id_tree_element.get("id")] = { "index": _len_resource, "type": resource_id_tree_element.get("type"), "name": resource_id_tree_element.get("name"), "size": 0, "reachable": [_len_resource] }
        if not resource_id_tree_element.get("type") in _resource_idx_by_name.keys():
            _resource_idx_by_name[resource_id_tree_element.get("type")] = {}
        _resource_idx_by_name[resource_id_tree_element.get("type")][resource_id_tree_element.get("name")] = (resource_id_tree_element.get("id"), _len_resource)
        _len_resource = _len_resource + 1

    return _resource_dict, _resource_idx_by_name

# Explore assets directory and make asset dictionary with all files in assets directory
def get_asset_dict(resources_dict):
    _asset_dict = {}
    _len_asset = len(resources_dict)

    asset_path = TEMP_PATH + "/assets/"

    for dirpath, dirnames, filenames in os.walk(asset_path):
        try:
            for filename in filenames:
                _asset_dict[os.path.join(dirpath,filename)] = {"size": os.path.getsize(os.path.join(dirpath,filename)), "index": _len_asset}
                _len_asset = _len_asset + 1
        except OSError:
            raise Exception('Asset File Size Fetching Failed : Check permission settings on your home folder.')

    return _asset_dict

# Merge all drawables into one folder
def merge_drawables():
    tempd_path = TEMP_PATH + "/temp_drawable"
    if not os.path.exists(tempd_path):
        os.makedirs(tempd_path)
    drawable_folders = subprocess.check_output(['find', TEMP_PATH+"/res", "-name", "drawable*"])
    drawable_path = ""
    drawable_folders = drawable_folders.split("\n")[:-1]

    density = ['ldpi', 'mdpi', 'hdpi', 'xhdpi', 'xxhdpi', 'xxxhdpi']
    exisiting_density = ['','','','','','']
    chosen_density_path = ""

    for df in drawable_folders:
        # Search for ldpi, mdpi, hdpi, xhdpi, xxhdpi, xxxhdpi
        for s in df.split("-"):
            if s in density:
                exisiting_density[density.index(s)] = df
        # find base folder (drawable)
        if df[-8:] == "drawable" and not "xml" in df:
            drawable_path = df
    if drawable_path != "":
        p = subprocess.Popen("rsync -a "+drawable_path+"/* "+tempd_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
        p.communicate()
        p2 = subprocess.Popen("rm -rf "+drawable_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
        p2.communicate()
    else:
        print "Drawable base folder is missing!"

    exisiting_density = [value for value in exisiting_density if value != ""]
    # find medium and add first
    if len(exisiting_density) > 0:
        chosen_density_path = exisiting_density[len(exisiting_density)//2]
        p = subprocess.Popen("rsync -a --ignore-existing "+chosen_density_path+"/* "+tempd_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
        p.communicate()
        p2 = subprocess.Popen("rm -rf "+chosen_density_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
        p2.communicate()

    # for others, merge with base folder (ignore for duplicate)
    drawable_folders = subprocess.check_output(['find', TEMP_PATH+"/res", "-name", "drawable*"])
    drawable_folders = drawable_folders.split("\n")[:-1]
    for df in drawable_folders:
        if "xml" in df:
            pass
        else:
            p = subprocess.Popen("rsync -a --ignore-existing "+df+"/* "+tempd_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
            p.communicate()
            p2 = subprocess.Popen("rm -rf "+df, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
            p2.communicate()
        
    p3 = subprocess.Popen("mv "+tempd_path+" "+drawable_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    p3.communicate()

# Merge all mipmaps into one folder
def merge_mipmaps():
    tempm_path = TEMP_PATH + "/temp_mipmaps"
    if not os.path.exists(tempm_path):
        os.makedirs(tempm_path)
    mipmap_folders = subprocess.check_output(['find', TEMP_PATH+"/res", "-name", "mipmap*"])
    mipmap_folders = mipmap_folders.split("\n")[:-1]

    mipmap_path = TEMP_PATH+"/res/mipmap"
    if not os.path.exists(mipmap_path):
        os.makedirs(mipmap_path)

    density = ['ldpi', 'mdpi', 'hdpi', 'xhdpi', 'xxhdpi', 'xxxhdpi']
    exisiting_density = ['','','','','','']
    chosen_density_path = ""

    for mf in mipmap_folders:
        # Search for ldpi, mdpi, hdpi, xhdpi, xxhdpi, xxxhdpi
        for s in mf.split("-"):
            if s in density:
                exisiting_density[density.index(s)] = mf

    exisiting_density = [value for value in exisiting_density if value != ""]
    # find medium and add first
    if len(exisiting_density) > 0:
        chosen_density_path = exisiting_density[len(exisiting_density)//2]
        p = subprocess.Popen("rsync -a "+chosen_density_path+"/* "+tempm_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
        p.communicate()
        p2 = subprocess.Popen("rm -rf "+chosen_density_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
        p2.communicate()

    # for others, merge with base folder (ignore for duplicate)
    mipmap_folders = subprocess.check_output(['find', TEMP_PATH+"/res", "-name", "mipmap*"])
    mipmap_folders = mipmap_folders.split("\n")[:-1]
    for mf in mipmap_folders:
        if "xml" in mf:
            pass
        else:
            p = subprocess.Popen("rsync -a --ignore-existing"+mf+"/* "+tempm_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
            p.communicate()
            p2 = subprocess.Popen("rm -rf "+mf, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
            p2.communicate()
        
    p = subprocess.Popen("rsync -a "+mipmap_path+"/* "+tempm_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    p.communicate()
    p2 = subprocess.Popen("rm -rf "+mipmap_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    p2.communicate()
    p3 = subprocess.Popen("mv "+tempm_path+" "+mipmap_path, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    p3.communicate()

def build_method_dependency_graph(ec_dir, pickle, resources_dict, assets_dict):
    ec_files = [os.path.join(ec_dir, f) for f in os.listdir(ec_dir) if os.path.isfile(os.path.join(ec_dir, f))]
    smalitree = get_covered_smalitree(ec_files, pickle)

    st1 = time.time()

    _vertices = []
    _edges = []
    _methods = []
    _classes = []
    _chg = {}
    _rev_chg = {}
    _reachable = {}
    _len_methods = len(assets_dict) + len(resources_dict)
    _idx_method = 0
    _class_method_idx = {}


    for cl in smalitree.classes:
        class_name = os.path.join(cl.folder,cl.file_name)[:-6]
        dir = os.path.join(TEMP_PATH+"/smali/", cl.folder)
        if not os.path.exists(dir):
            os.makedirs(dir)

        buf = [LI_TAG(d) for d in cl.get_class_description()]
        buf.append(LI_TAG(''))
        buf.extend([LI_TAG(a) for a in cl.get_annotations()])
        buf.append(LI_TAG(''))
        buf.extend([LI_TAG(f) for f in cl.get_fields()])
        buf.append(LI_TAG(''))

        _classes = _classes + [{'name': class_name, 'buf': buf}]
        _class_method_idx[class_name] = {}

        for class_desc_line in cl.get_class_description():
            if ".super" in class_desc_line:
                pcln = class_desc_line.split(' ')[-1][:-1]
                if pcln[0] == 'L':
                    pcln = pcln[1:]
                if class_name in _rev_chg.keys():
                    _rev_chg[class_name].append(pcln) 
                else:
                    _rev_chg[class_name] = [pcln]

                if pcln in _chg.keys():
                    _chg[pcln].append(class_name) 
                else:
                    _chg[pcln] = [class_name]

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
                ins_buf.append(add_tab(ins.buf))
                _cost = _cost + utf8len(ins.buf)


            count = 0
            for l in labels:
                ins_buf.insert(l.index + count, add_tab(l.buf))
                _cost = _cost + utf8len(l.buf)
                count += 1

                for t in l.tries:
                    ins_buf.insert(l.index + count, add_tab(t.buf))
                    _cost = _cost + utf8len(t.buf)
                    count += 1

                if l.switch:
                    for sl in l.switch.buf:
                        ins_buf.insert(l.index + count, add_tab(sl))
                        _cost = _cost + utf8len(sl)
                        count += 1

                if l.array_data:
                    for sl in l.array_data.buf:
                        ins_buf.insert(l.index + count, add_tab(sl))
                        _cost = _cost + utf8len(sl)
                        count += 1

            ins_buf.insert(0, LI_TAG(''))
            _cost = _cost + utf8len('')

            for a in m.annotations:
                a.reload()
                ins_buf[0:0] = [add_tab(d) for d in a.buf]
            for p in reversed(m.parameters):
                p.reload()
                ins_buf[0:0] = [add_tab(d) for d in p.buf]

            ins_buf.insert(0,add_tab(m.get_registers_line() ) )
            _cost = _cost + utf8len(m.get_registers_line())

            ins_buf.insert(0,m.get_method_line())
            ins_buf.append(LI_TAG(".end method"))
            ins_buf.append(LI_TAG(''))

            _cost = _cost + utf8len(m.get_method_line())
            _cost = _cost + utf8len(".end method")
            _cost = _cost + utf8len('')

            _class_method_idx[class_name][m.get_desc()] = _idx_method
            _idx_method = _idx_method + 1
            _methods = _methods + [{'class': class_name, 'name': m.get_desc(),'buf': ins_buf, 'size': _cost, 'res': [_len_methods]}]
            _len_methods = _len_methods + 1

            if called:
                _vertices = _vertices + [1]
            else:
                _vertices = _vertices + [0]

    searched_parent = []
    searched_child = []

    st = time.time()

    print "Node Loading : "+str(int(st-st1))

    # Using CHG, search reachable class indexes
    for clnidx in tqdm(range(len(_chg.keys()))):
        cln = _chg.keys()[clnidx]
        _reachable[cln] = [cln]
        # Search for all parent
        parent_target = None
        if cln in _rev_chg.keys():
            parent_target = _rev_chg[cln]
        while parent_target:
            if type(parent_target) == type([]):
                parent_target = parent_target[0]
            if parent_target in _reachable.keys():
                _reachable[cln] = _reachable[cln] + _reachable[parent_target] + [parent_target]
                break
            _reachable[cln] = _reachable[cln] + [parent_target]
            if parent_target in _rev_chg.keys():
                parent_target = _rev_chg[parent_target]
            else:
                parent_target = None
        # Search for all child
        child_targets = []
        if cln in _chg.keys():
            child_targets = [cln]
        while len(child_targets) > 0:
            child_target = child_targets[0]
            if type(child_target) == type([]):
                child_target = child_target[0]
            if child_target in _reachable.keys():
                _reachable[cln] = _reachable[cln] + _reachable[child_target] + [child_target]
                child_targets.pop(0)
                continue
            _reachable[cln] = _reachable[cln] + [child_target] 
            if child_target in _chg.keys():
                _reachable[cln] = _reachable[cln] + _chg[child_target]
                child_targets = child_targets + _chg[child_target]
            child_targets.pop(0)
        _reachable[cln] = list(set(_reachable[cln]))
        # print "----------------"+cln+"----------------"
        # print _reachable[cln]

    et = time.time()
    print "reachable calculation : "+str(int(et-st))

    for i in tqdm(range(len(_methods))):
        searched = []
        m = _methods[i]
        for ins in m['buf']:
            # XML Parsing is spending too much time
            for resource_id, resource in resources_dict.items():
                if resource['name'] in ins or resource_id in ins:
                    _methods[i]['res'] = _methods[i]['res'] + resources_dict[resource_id]['reachable']

            for asset_name in assets_dict.keys():
                if len(asset_name.split(TEMP_PATH + "/assets/")) > 1 and asset_name.split(TEMP_PATH + "/assets/")[1] in ins:
                    _methods[i]['res'] = _methods[i]['res'] + [assets_dict[asset_name]['index']]

            # edge building
            is_call = re.search("^\tinvoke-", ins)
            is_super = re.search("^\tinvoke-super", ins)
            if is_call:
                class_name = ins.split(" ")[-1].split("->")[0][1:-1]
                if len(class_name) >= 1 and class_name[0] == 'L':
                    class_name = class_name[1:]
                method_name = ins.split(" ")[-1].split("->")[1]

                # resource usage check
                # XML Parsing is spending too much time
                if "getIdentifier" in method_name:
                    string_ref = re.compile('"[a-zA-Z0-9_.$]*"')
                    for sins in m['buf']:
                        strings = string_ref.findall(sins)
                        for s in strings:
                            if len(s) < 4:
                                continue
                            if s[1:-1] == "":
                                continue
                            if s in searched:
                                continue
                            searched = searched + [s]
                            print "String "+s+" Found!"
                            for resource_id, resource in resources_dict.items():
                                if s[1:-1] in resource['name']:
                                    _methods[i]['res'] = _methods[i]['res'] + resources_dict[resource_id]['reachable']
                                    print resource['name']+" is in method "+m['name']+"!"
                # method_name => idx_set
                # Ignore Class Hierarchy For Now..?



                # invoke-super only version (more precise)
                '''
                if is_super:
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
                '''
                if class_name in _reachable.keys():
                    for clnsidx in range(len(_reachable[class_name])):
                        clns = _reachable[class_name][clnsidx]
                        if clns in _class_method_idx.keys():
                            if method_name in _class_method_idx[clns].keys():
                                _edges = _edges + [(_methods.index(m),_class_method_idx[clns][method_name])]

    _costs = []
    _total_cost = 0
    _res_cost = 0
    _asset_cost = 0
    _method_cost = 0
    _asset_node = 0
    _method_node = 0
    _attr_node = 0

    for res_key, res_elem in resources_dict.items():
        _costs = _costs + [ res_elem["size"] ]
        _total_cost = _total_cost + res_elem["size"]
        _res_cost = _res_cost + res_elem["size"]
        _attr_node = _attr_node + 1
    for asset_key, asset_elem in assets_dict.items():
        _costs = _costs + [ asset_elem["size"] ]
        _total_cost = _total_cost + asset_elem["size"]
        _asset_cost = _asset_cost + asset_elem["size"]
        _asset_node = _asset_node + 1
    for _m in _methods:
        _costs = _costs + [ _m["size"] ]
        _total_cost = _total_cost + _m["size"]
        _method_cost = _method_cost + _m["size"]
        _method_node = _method_node + 1

    print "Resource Cost : "+str(_res_cost)
    print "Asset Cost : "+str(_asset_cost)
    print "Method Cost : "+str(_method_cost)
    print "Total Cost : "+str(_total_cost)
    print "# of Asset Nodes : "+str(_asset_node)
    print "# of Method Nodes : "+str(_method_node)
    print "# of Attr Nodes : "+str(_attr_node)
    return _costs, _edges, _vertices, _methods, _classes

def parseAndroidManifest(resource_dict, resource_idx_by_name):
    resource_ref = re.compile("@[a-z:/\{\}]+/[a-zA-Z0-9_.$]+")
    style_ref = re.compile("\?[a-z:/\{\}]+[a-zA-Z0-9_.$]+")

    androidmanifest_tree = ET.parse(TEMP_PATH + "/AndroidManifest.xml")
    androidmanifest_root = androidmanifest_tree.getroot()
    androidmanifest_res = []
    resource_ref_size = 0
    resource_ref_child = []
    style_ref_size = 0
    style_ref_child = []
    for androidmanifest_value in androidmanifest_root.iter():
        if type(androidmanifest_value.text) == str and style_ref.match(androidmanifest_value.text):
            androidmanifest_value_text = androidmanifest_value.text.replace("?","")
            androidmanifest_value_text = androidmanifest_value_text.split('}')[-1]
            androidmanifest_value_text = androidmanifest_value_text.split(':')[-1]
            if len(androidmanifest_value_text.split("/")) > 1:
                if androidmanifest_value_text.split("/")[0] in resource_idx_by_name.keys():
                    if androidmanifest_value_text.split("/")[1] in resource_idx_by_name[androidmanifest_value_text.split("/")[0]].keys():
                        target = resource_idx_by_name[androidmanifest_value_text.split("/")[0]][androidmanifest_value_text.split("/")[1]]
                        androidmanifest_res = androidmanifest_res + [target[1]]
            else: 
                if "attr" in resource_idx_by_name.keys():
                    if androidmanifest_value_text.split("/")[-1] in resource_idx_by_name["attr"].keys():
                        target = resource_idx_by_name["attr"][androidmanifest_value_text.split("/")[-1]]
                        androidmanifest_res = androidmanifest_res + [resource_dict[target[0]]["reachable"]]
        if type(androidmanifest_value.text) == str and resource_ref.match(androidmanifest_value.text):
            androidmanifest_value_text = androidmanifest_value.text.replace("@","")
            androidmanifest_value_text = androidmanifest_value_text.split('}')[-1]
            androidmanifest_value_text = androidmanifest_value_text.split(':')[-1]
            if androidmanifest_value_text.split("/")[0] in resource_idx_by_name.keys():
                if androidmanifest_value_text.split("/")[1] in resource_idx_by_name[androidmanifest_value_text.split("/")[0]].keys():
                    target = resource_idx_by_name[androidmanifest_value_text.split("/")[0]][androidmanifest_value_text.split("/")[1]]
                    androidmanifest_res = androidmanifest_res + [target[1]]
        for androidmanifest_attrib_value in androidmanifest_value.attrib.values():
            if style_ref.match(androidmanifest_attrib_value):
                androidmanifest_attrib_value = androidmanifest_attrib_value.replace("?","")
                androidmanifest_attrib_value = androidmanifest_attrib_value.split('}')[-1]
                androidmanifest_attrib_value = androidmanifest_attrib_value.split(':')[-1]
                if len(androidmanifest_attrib_value.split("/")) > 1:
                    if androidmanifest_attrib_value.split("/")[0] in resource_idx_by_name.keys():
                        if androidmanifest_attrib_value.split("/")[1] in resource_idx_by_name[androidmanifest_attrib_value.split("/")[0]].keys():
                            target = resource_idx_by_name[androidmanifest_attrib_value.split("/")[0]][androidmanifest_attrib_value.split("/")[1]]
                            androidmanifest_res = androidmanifest_res + [target[1]]
                else: 
                    if "attr" in resource_idx_by_name.keys():
                        if androidmanifest_attrib_value.split("/")[-1] in resource_idx_by_name["attr"].keys():
                            target = resource_idx_by_name["attr"][androidmanifest_attrib_value.split("/")[-1]]
                            androidmanifest_res = androidmanifest_res + [target[1]]
            if resource_ref.match(androidmanifest_attrib_value):
                androidmanifest_attrib_value = androidmanifest_attrib_value.replace("@","")
                androidmanifest_attrib_value = androidmanifest_attrib_value.split('}')[-1]
                androidmanifest_attrib_value = androidmanifest_attrib_value.split(':')[-1]
                if androidmanifest_attrib_value.split("/")[0] in resource_idx_by_name.keys():
                    if androidmanifest_attrib_value.split("/")[1] in resource_idx_by_name[androidmanifest_attrib_value.split("/")[0]].keys():
                        target = resource_idx_by_name[androidmanifest_attrib_value.split("/")[0]][androidmanifest_attrib_value.split("/")[1]]
                        androidmanifest_res = androidmanifest_res + [target[1]]
        for androidmanifest_value_item in androidmanifest_value.iter():
            if type(androidmanifest_value_item.text) == str and style_ref.match(androidmanifest_value_item.text):
                androidmanifest_value_item_text = androidmanifest_value_item.text.replace("?","")
                androidmanifest_value_item_text = androidmanifest_value_item_text.split('}')[-1]
                androidmanifest_value_item_text = androidmanifest_value_item_text.split(':')[-1]
                ref_idx = None
                if len(androidmanifest_value_item_text.split("/")) > 1:
                    if androidmanifest_value_item_text.split("/")[0] in resource_idx_by_name.keys():
                        if androidmanifest_value_item_text.split("/")[1] in resource_idx_by_name[androidmanifest_value_item_text.split("/")[0]].keys():
                            ref_idx = resource_idx_by_name[androidmanifest_value_item_text.split("/")[0]][androidmanifest_value_item_text.split("/")[1]]
                else: 
                    if "attr" in resource_idx_by_name.keys():
                        if androidmanifest_value_item_text.split("/")[-1] in resource_idx_by_name["attr"].keys():
                            ref_idx = resource_idx_by_name["attr"][androidmanifest_value_item_text.split("/")[-1]]
                    else:
                        if androidmanifest_value_item_text.split("/")[-1] in resource_idx_by_name["item"].keys():
                            ref_idx = resource_idx_by_name["item"][androidmanifest_value_item_text.split("/")[-1]]
                if ref_idx:
                    androidmanifest_res = androidmanifest_res + [ref_idx[1]]
            if type(androidmanifest_value_item.text) == str and resource_ref.match(androidmanifest_value_item.text):
                androidmanifest_value_item_text = androidmanifest_value_item.text.replace("@","")
                androidmanifest_value_item_text = androidmanifest_value_item_text.split('}')[-1]
                ref_idx = None
                if androidmanifest_value_item_text.split("/")[0] in resource_idx_by_name.keys():
                    if androidmanifest_value_item_text.split("/")[1] in resource_idx_by_name[androidmanifest_value_item_text.split("/")[0]].keys():
                        ref_idx = resource_idx_by_name[androidmanifest_value_item_text.split("/")[0]][androidmanifest_value_item_text.split("/")[1]]
                if ref_idx:
                    androidmanifest_res = androidmanifest_res + [ref_idx[1]]
            
            for androidmanifest_item_attrib_val in androidmanifest_value_item.attrib.values():
                if style_ref.match(androidmanifest_item_attrib_val):
                    androidmanifest_item_attrib_val = androidmanifest_item_attrib_val.replace("?","")
                    androidmanifest_item_attrib_val = androidmanifest_item_attrib_val.split('}')[-1]
                    androidmanifest_item_attrib_val = androidmanifest_item_attrib_val.split(':')[-1]
                    ref_idx = None
                    if len(androidmanifest_item_attrib_val.split("/")) > 1:
                        if androidmanifest_item_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                            if androidmanifest_item_attrib_val.split("/")[1] in resource_idx_by_name[androidmanifest_item_attrib_val.split("/")[0]].keys():
                                ref_idx = resource_idx_by_name[androidmanifest_item_attrib_val.split("/")[0]][androidmanifest_item_attrib_val.split("/")[1]]
                    else: 
                        if "attr" in resource_idx_by_name.keys():
                            if androidmanifest_item_attrib_val.split("/")[-1] in resource_idx_by_name["attr"].keys():
                                ref_idx = resource_item_attrib_val["attr"][androidmanifest_item_attrib_val.split("/")[-1]]
                        else:
                            if androidmanifest_item_attrib_val.split("/")[-1] in resource_idx_by_name["item"].keys():
                                ref_idx = resource_idx_by_name["item"][androidmanifest_item_attrib_val.split("/")[-1]]
                    if ref_idx:
                        androidmanifest_res = androidmanifest_res + [ref_idx[1]]
                if resource_ref.match(androidmanifest_item_attrib_val):
                    androidmanifest_item_attrib_val = androidmanifest_item_attrib_val.replace("@","")
                    androidmanifest_item_attrib_val = androidmanifest_item_attrib_val.split('}')[-1]
                    androidmanifest_item_attrib_val = androidmanifest_item_attrib_val.split(':')[-1]
                    ref_idx = None
                    if androidmanifest_item_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                        if androidmanifest_item_attrib_val.split("/")[1] in resource_idx_by_name[androidmanifest_item_attrib_val.split("/")[0]].keys():
                            ref_idx = resource_idx_by_name[androidmanifest_item_attrib_val.split("/")[0]][androidmanifest_item_attrib_val.split("/")[1]]
                    if ref_idx:
                        androidmanifest_res = androidmanifest_res + [ref_idx[1]]
    androidmanifest_res = list(set(androidmanifest_res))
    return androidmanifest_res

# remove PulP
def solve_ilp(costs, edges, vertices, methods, init_resources, resources, saved_model=None):
    ilp_frontpart = ["\\* Coverage_Maximizing_Problem *\\\n"]
    ilp_frontpart.append("Maximize\nOBJ: ")
    ilp_backpart = ["\nBinaries\n"]
    if not saved_model:
        for p in range(len(vertices)):
            if p > 0:
                ilp_frontpart.append(" + ")
            ilp_frontpart.append("x_" + str(p))
        ilp_frontpart.append("\nSubject To\n")
        cond_counter = 1
        for v in range(0,len(vertices)):
            if vertices[v] != 1:
                if any(edge[1] == v and edge[0] != v  for edge in edges):
                    ilp_frontpart.append("_C"+str(cond_counter)+": ")
                    cond_counter = cond_counter + 1
                    starter = True
                    for x_no in [edge[0] for edge in edges if edge[1]==v and edge[0] != v]:
                        if starter:
                            ilp_frontpart.append("x_"+str(x_no))
                            starter = False
                        else:
                            ilp_frontpart.append(" + x_"+str(x_no))
                    ilp_frontpart.append(" - x_"+str(v)+" >= 0\n")
        for i in range(0,len(costs)):
            for v in range(len(vertices)):
                if i in methods[v]['res']:
                    ilp_frontpart.append("_C"+str(cond_counter)+": ")
                    cond_counter = cond_counter + 1
                    ilp_frontpart.append("r_"+str(i)+" - x_"+str(v)+" >= 0\n")
        for v in range(0,len(vertices)):
            if vertices[v] == 1:
                ilp_frontpart.append("_C"+str(cond_counter)+": ")
                cond_counter = cond_counter + 1
                ilp_frontpart.append("x_"+str(v)+" = 1\n")
        for ir in init_resources:
            ilp_frontpart.append("_C"+str(cond_counter)+": ")
            cond_counter = cond_counter + 1
            ilp_frontpart.append("r_"+str(ir)+" = 1\n")
        for r in resources.values():
            for rch in r["reachable"]:
                if rch != r["index"]:
                    ilp_frontpart.append("_C"+str(cond_counter)+": ")
                    cond_counter = cond_counter + 1
                    ilp_frontpart.append("r_"+str(rch)+" - r_"+str(r["index"])+" >= 0\n")
        for i in range(len(costs)):
            ilp_frontpart.append("_C"+str(cond_counter)+": ")
            cond_counter = cond_counter + 1
            ilp_frontpart.append("r_"+str(i)+" >= 0\n")
        ilp_frontpart.append("_C"+str(cond_counter)+": ")
        cond_counter = cond_counter + 1
        for v in range(0,len(costs)):
            if v == 0:
                ilp_frontpart.append(str(costs[v]) + " r_"+str(v))
            else:
                ilp_frontpart.append(" + " + str(costs[v]) + " r_"+str(v))
        ilp_frontpart.append(" <= ")
        for v in range(len(vertices)):
            ilp_backpart.append("x_" + str(v) + "\n")
        for v in range(len(costs)):
            ilp_backpart.append("r_" + str(v) + "\n")
        ilp_backpart.append("End\n")
    else:
        ilp_frontpart = saved_model[0]
        ilp_backpart = saved_model[1]

    ilp_full = ilp_frontpart + [str(DEMO_SIZE_LIMIT)] + ilp_backpart

    open(TEMP_PATH_ILP + "/ilp_"+str(dupchecker)+".lp", "wb").write(''.join(ilp_full))

    solve_ilp_process = subprocess.call("glpsol --lp "+TEMP_PATH_ILP + "/ilp_"+str(dupchecker)+".lp --tmlim 600 -o "+TEMP_PATH_ILP + "/ilp_"+str(dupchecker)+".sol", shell=True)

    x_val = [0]*len(vertices)
    r_val = [0]*len(costs)

    with open(TEMP_PATH_ILP + "/ilp_"+str(dupchecker)+".sol") as solfile:
        for line in solfile:
            if "Status:" in line:
                if not "OPTIMAL" in line:
                    return None, None, (ilp_frontpart, ilp_backpart)
            ll = line.split()
            if len(ll) == 6 and ('x_' in ll[1] or 'r_' in ll[1]):
                if 'x_' in ll[1]:
                    x_val[int(ll[1][2:])] = int(ll[3])
                if 'r_' in ll[1]:
                    r_val[int(ll[1][2:])] = int(ll[3])
        return x_val, r_val, (ilp_frontpart, ilp_backpart)
    return None, None, (ilp_frontpart, ilp_backpart)

def generate_smali_code(vertices, classes, methods):
    FNULL = open(os.devnull, 'w')
    delete_original_smali = subprocess.call("rm -rf "+TEMP_PATH+"/smali", shell=True, stdout=FNULL)
    output_dir = TEMP_PATH+"/smali/"
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


def purge_assets(assets_dict, resources):
    change = 0
    if os.path.exists(TEMP_PATH + "/assets"):
        for dirpath, dirnames, filenames in os.walk(TEMP_PATH + "/assets"):
            for filename in filenames:
                if resources[assets_dict[os.path.join(dirpath,filename)]['index']] != 1:
                    os.remove(os.path.join(dirpath,filename))
                    change = change + 1
    return change

def purge_resources(resources_dict, assets_dict, resources):
    change = 0
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
                    if (child.tag == "string-array" or child.tag == "integer-array") and get_resource_info_by_name(resource_dict, "array", child.get("name"))['index'] != -1 and resources[get_resource_info_by_name(resource_dict, "array", child.get("name"))['index']] != 1:
                        cond_checker = True
                    if child.get("type") and get_resource_info_by_name(resource_dict, child.get("type"), child.get("name"))['index'] != -1 and resources[get_resource_info_by_name(resource_dict, child.get("type"), child.get("name"))['index']] != 1:
                        cond_checker = True
                    if child.get("type") and (child.get("type") == "string-array" or child.get("type") == "integer-array") and get_resource_info_by_name(resource_dict, "array", child.get("name"))['index'] != -1 and resources[get_resource_info_by_name(resource_dict, "array", child.get("name"))['index']] != 1:
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

    repack_process = subprocess.call("apktool b "+TEMP_PATH+" -o "+outdir+"reduced_temp_"+str(dupchecker)+".apk -f", shell=True, stdout=FNULL)
    
    if repack_process != 0:
        raise Exception('Unpacking Failed : Check if apktool is installed properly.')

    if os.path.getsize(outdir+"reduced_temp_"+str(dupchecker)+".apk") < APK_SIZE_LIMIT:
        return 1
    else:
        return 0

def remove_duplicated_files():
    drawable_path = TEMP_PATH+"/res/drawable"
    drawable_list = []
    mipmap_path = TEMP_PATH+"/res/mipmap"
    mipmap_list = []
    for dirpath, dirnames, filenames in os.walk(drawable_path):
        for filename in filenames:
            no_ext = os.path.splitext(filename)[0]
            if no_ext in drawable_list:
                p2 = subprocess.Popen("rm -rf "+dirpath+"/"+filename, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
            else:
                drawable_list = drawable_list + [no_ext]

    for dirpath, dirnames, filenames in os.walk(mipmap_path):
        for filename in filenames:
            no_ext = os.path.splitext(filename)[0]
            if no_ext in mipmap_list:
                p2 = subprocess.Popen("rm -rf "+dirpath+"/"+filename, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
            else:
                mipmap_list = mipmap_list + [no_ext]

def calculate_resource_size(resource_dict, assets_dict, resource_idx_by_name):
    resource_idx_by_name["item"] = {}
    # https://developer.android.com/guide/topics/resources/providing-resources#ResourcesFromXml
    # Accessing other resources affects resource usage
    resource_ref = re.compile("@[a-z:/\{\}]+/[a-zA-Z0-9_.$]+")
    # https://developer.android.com/guide/topics/resources/providing-resources#ReferencesToThemeAttributes
    style_ref = re.compile("\?[a-z:/\{\}]+[a-zA-Z0-9_.$]+")
    android_res = "{http://schemas.android.com/apk/res/android"

    asset_names_short = []

    for asset_name in assets_dict.keys():
        if len(asset_name.split(TEMP_PATH + "/assets/")) > 1:
            asset_names_short.append(asset_name.split(TEMP_PATH + "/assets/")[1])

    for dirpath, dirnames, filenames in os.walk(TEMP_PATH + "/res"):
        for filename in filenames:
            if "values" in os.path.basename(dirpath) and filename == "public.xml":
                continue
            elif "values" in os.path.basename(dirpath) and filename != "public.xml":
                tree = ET.parse(os.path.join(dirpath,filename))
                root = tree.getroot()
                for child in root:
                    res_idx =  None
                    if "type" in child.attrib.keys() and child.attrib["type"] in resource_idx_by_name.keys():
                        if child.get("name") in resource_idx_by_name[child.attrib["type"]].keys():
                            res_idx = resource_idx_by_name[child.attrib["type"]][child.get("name")]

                    if "type" in child.attrib.keys() and (child.attrib["type"] == "integer-array" or child.attrib["type"] == "string-array"):
                        if child.get("name") in resource_idx_by_name["array"].keys():
                            res_idx = resource_idx_by_name["array"][child.get("name")]

                    if not res_idx:
                        if child.tag in resource_idx_by_name.keys():
                            if child.get("name") in resource_idx_by_name[child.tag].keys():
                                res_idx = resource_idx_by_name[child.tag][child.get("name")]
                        else:
                            if child.tag == "integer-array" or child.tag == "string-array":
                                if child.get("name") in resource_idx_by_name["array"].keys():
                                    res_idx = resource_idx_by_name["array"][child.get("name")]

                    if not res_idx:
                        continue
                    resource_dict[res_idx[0]]["size"] = resource_dict[res_idx[0]]["size"] + utf8len(ET.tostring(child))

                    # Finding Asset Usage
                    for ans in asset_names_short:
                        if ans in ET.tostring(child):
                            print ans + " in " + resource_dict[res_idx[0]]["name"]
                            print assets_dict[TEMP_PATH + "/assets/"+ans]['index']
                            resource_dict[res_idx[0]]["reachable"].append(assets_dict[TEMP_PATH + "/assets/"+ans]['index'])

                    # Finding Reference to Style Attr in value
                    if type(child.text) == str and style_ref.match(child.text):
                        resource_value_text = child.text.replace("?","")
                        resource_value_text = resource_value_text.split('}')[-1]
                        resource_value_text = resource_value_text.split(':')[-1]
                        ref_idx = None
                        if len(resource_value_text.split("/")) > 1:
                            if resource_value_text.split("/")[0] in resource_idx_by_name.keys():
                                if resource_value_text.split("/")[1] in resource_idx_by_name[resource_value_text.split("/")[0]].keys():
                                    ref_idx = resource_idx_by_name[resource_value_text.split("/")[0]][resource_value_text.split("/")[1]]
                        else: 
                            if "attr" in resource_idx_by_name.keys():
                                if resource_value_text.split("/")[-1] in resource_idx_by_name["attr"].keys():
                                    ref_idx = resource_idx_by_name["attr"][resource_value_text.split("/")[-1]]
                            else:
                                if resource_value_text.split("/")[-1] in resource_idx_by_name["item"].keys():
                                    ref_idx = resource_idx_by_name["item"][resource_value_text.split("/")[-1]]
                        if ref_idx:
                            resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]

                    # Finding access resource from XML in value
                    if type(child.text) == str and resource_ref.match(child.text):
                        resource_value_text = child.text.replace("@","")
                        resource_value_text = resource_value_text.split('}')[-1]
                        resource_value_text = resource_value_text.split(':')[-1]
                        ref_idx = None
                        if resource_value_text.split("/")[0] in resource_idx_by_name.keys():
                            if resource_value_text.split("/")[1] in resource_idx_by_name[resource_value_text.split("/")[0]].keys():
                                ref_idx = resource_idx_by_name[resource_value_text.split("/")[0]][resource_value_text.split("/")[1]]
                        if ref_idx:
                            resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]

                    # Searching Access and Reference in Attributes
                    for resource_attrib_key, resource_attrib_val in child.attrib.items():
                        if not android_res in resource_attrib_key:
                            ref_idx = None
                            if "attr" in resource_idx_by_name.keys():
                                if resource_attrib_key.split("}")[-1] in resource_idx_by_name["attr"].keys():
                                    ref_idx = resource_idx_by_name["attr"][resource_attrib_key.split("}")[-1]]
                            else:
                                if resource_attrib_key.split("}")[-1] in resource_idx_by_name["item"].keys():
                                    ref_idx = resource_idx_by_name["item"][resource_attrib_key.split("}")[-1]]
                            if ref_idx:
                                resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                            
                        if style_ref.match(resource_attrib_val):
                            resource_attrib_val = resource_attrib_val.replace("?","")
                            resource_attrib_val = resource_attrib_val.split('}')[-1]
                            resource_attrib_val = resource_attrib_val.split(':')[-1]
                            ref_idx = None
                            if len(resource_attrib_val.split("/")) > 1:
                                if resource_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                                    if resource_attrib_val.split("/")[1] in resource_idx_by_name[resource_attrib_val.split("/")[0]].keys():
                                        ref_idx = resource_idx_by_name[resource_attrib_val.split("/")[0]][resource_attrib_val.split("/")[1]]
                            else: 
                                if "attr" in resource_idx_by_name.keys():
                                    if resource_attrib_val.split("/")[-1] in resource_idx_by_name["attr"].keys():
                                        ref_idx = resource_idx_by_name["attr"][resource_attrib_val.split("/")[-1]]
                                else:
                                    if resource_attrib_val.split("/")[-1] in resource_idx_by_name["item"].keys():
                                        ref_idx = resource_idx_by_name["item"][resource_attrib_val.split("/")[-1]]
                            if ref_idx:
                                resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                        if resource_ref.match(resource_attrib_val):
                            resource_attrib_val = resource_attrib_val.replace("@","")
                            resource_attrib_val = resource_attrib_val.split('}')[-1]
                            resource_attrib_val = resource_attrib_val.split(':')[-1]
                            ref_idx = None
                            if resource_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                                if resource_attrib_val.split("/")[1] in resource_idx_by_name[resource_attrib_val.split("/")[0]].keys():
                                    ref_idx = resource_idx_by_name[resource_attrib_val.split("/")[0]][resource_attrib_val.split("/")[1]]
                            if ref_idx:
                                resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]

                    # Searching Access and Reference in value, attributes of child elements
                    # We assume that there is no child element depth of 2
                    for resource_value_item in child.iter():
                        if "name" in resource_value_item.attrib.keys():
                            resource_idx_by_name["item"][resource_value_item.attrib["name"]] = res_idx
                            if "attr" in resource_idx_by_name.keys():
                                if resource_value_item.attrib["name"] in resource_idx_by_name["attr"].keys():
                                    target = resource_idx_by_name["attr"][resource_value_item.attrib["name"]]
                                    resource_dict[target[0]]["reachable"] = resource_dict[target[0]]["reachable"] + [res_idx[1]]
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [target[1]]
                            if "id" in resource_idx_by_name.keys():
                                if resource_value_item.attrib["name"] in resource_idx_by_name["id"].keys():
                                    target = resource_idx_by_name["id"][resource_value_item.attrib["name"]]
                                    resource_dict[target[0]]["reachable"] = resource_dict[target[0]]["reachable"] + [res_idx[1]]
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [target[1]]
                        if type(resource_value_item.text) == str and style_ref.match(resource_value_item.text):
                            resource_value_item_text = resource_value_item.text.replace("?","")
                            resource_value_item_text = resource_value_item_text.split('}')[-1]
                            resource_value_item_text = resource_value_item_text.split(':')[-1]
                            ref_idx = None
                            if len(resource_value_item_text.split("/")) > 1:
                                if resource_value_item_text.split("/")[0] in resource_idx_by_name.keys():
                                    if resource_value_item_text.split("/")[1] in resource_idx_by_name[resource_value_item_text.split("/")[0]].keys():
                                        ref_idx = resource_idx_by_name[resource_value_item_text.split("/")[0]][resource_value_item_text.split("/")[1]]
                            else: 
                                if "attr" in resource_idx_by_name.keys():
                                    if resource_value_item_text.split("/")[-1] in resource_idx_by_name["attr"].keys():
                                        ref_idx = resource_idx_by_name["attr"][resource_value_item_text.split("/")[-1]]
                                else:
                                    if resource_value_item_text.split("/")[-1] in resource_idx_by_name["item"].keys():
                                        ref_idx = resource_idx_by_name["item"][resource_value_item_text.split("/")[-1]]
                            if ref_idx:
                                resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                        if type(resource_value_item.text) == str and resource_ref.match(resource_value_item.text):
                            resource_value_item_text = resource_value_item.text.replace("@","")
                            resource_value_item_text = resource_value_item_text.split('}')[-1]
                            ref_idx = None
                            if resource_value_item_text.split("/")[0] in resource_idx_by_name.keys():
                                if resource_value_item_text.split("/")[1] in resource_idx_by_name[resource_value_item_text.split("/")[0]].keys():
                                    ref_idx = resource_idx_by_name[resource_value_item_text.split("/")[0]][resource_value_item_text.split("/")[1]]
                            if ref_idx:
                                resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                            
                        for resource_item_attrib_key, resource_item_attrib_val in resource_value_item.attrib.items():
                            if not android_res in resource_item_attrib_key:
                                ref_idx = None
                                if "attr" in resource_idx_by_name.keys():
                                    if resource_item_attrib_key.split("}")[-1] in resource_idx_by_name["attr"].keys():
                                        ref_idx = resource_idx_by_name["attr"][resource_item_attrib_key.split("}")[-1]]
                                else:
                                    if resource_item_attrib_key.split("}")[-1] in resource_idx_by_name["item"].keys():
                                        ref_idx = resource_idx_by_name["item"][resource_item_attrib_key.split("}")[-1]]
                                if ref_idx:
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                            if style_ref.match(resource_item_attrib_val):
                                resource_item_attrib_val = resource_item_attrib_val.replace("?","")
                                resource_item_attrib_val = resource_item_attrib_val.split('}')[-1]
                                resource_item_attrib_val = resource_item_attrib_val.split(':')[-1]
                                ref_idx = None
                                if len(resource_item_attrib_val.split("/")) > 1:
                                    if resource_item_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                                        if resource_item_attrib_val.split("/")[1] in resource_idx_by_name[resource_item_attrib_val.split("/")[0]].keys():
                                            ref_idx = resource_idx_by_name[resource_item_attrib_val.split("/")[0]][resource_item_attrib_val.split("/")[1]]
                                else: 
                                    if "attr" in resource_idx_by_name.keys():
                                        if resource_item_attrib_val.split("/")[-1] in resource_idx_by_name["attr"].keys():
                                            ref_idx = resource_item_attrib_val["attr"][resource_item_attrib_val.split("/")[-1]]
                                    else:
                                        if resource_item_attrib_val.split("/")[-1] in resource_idx_by_name["item"].keys():
                                            ref_idx = resource_idx_by_name["item"][resource_item_attrib_val.split("/")[-1]]
                                if ref_idx:
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                            if resource_ref.match(resource_item_attrib_val):
                                resource_item_attrib_val = resource_item_attrib_val.replace("@","")
                                resource_item_attrib_val = resource_item_attrib_val.split('}')[-1]
                                resource_item_attrib_val = resource_item_attrib_val.split(':')[-1]
                                ref_idx = None
                                if resource_item_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                                    if resource_item_attrib_val.split("/")[1] in resource_idx_by_name[resource_item_attrib_val.split("/")[0]].keys():
                                        ref_idx = resource_idx_by_name[resource_item_attrib_val.split("/")[0]][resource_item_attrib_val.split("/")[1]]
                                if ref_idx:
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                    resource_dict[res_idx[0]]["reachable"] = list(set(resource_dict[res_idx[0]]["reachable"]))
            else:
                res_type = dirpath.split('/')[-1].split('-')[0]
                res_name = os.path.splitext(filename)[0]
                res_idx =  None
                if res_type in resource_idx_by_name.keys():
                    if res_name in resource_idx_by_name[res_type].keys():
                        res_idx = resource_idx_by_name[res_type][res_name]
                if not res_idx:
                    continue

                try:
                    resource_dict[res_idx[0]]["size"] = resource_dict[res_idx[0]]["size"] + os.path.getsize(os.path.join(dirpath,filename))
                except OSError:
                    raise Exception('Resource File Size Fetching Failed : Check permission settings on your home folder.')

                # if resource is xml, parse it
                if os.path.splitext(filename)[1] == ".xml":
                    resource_file_tree = ET.parse(os.path.join(dirpath,filename))
                    resource_file_root = resource_file_tree.getroot()
                    for ans in asset_names_short:
                        if ans in ET.tostring(resource_file_root):
                            print ans + " in " + resource_dict[res_idx[0]]["name"]
                            print assets_dict[TEMP_PATH + "/assets/"+ans]['index']
                            resource_dict[res_idx[0]]["reachable"].append(assets_dict[TEMP_PATH + "/assets/"+ans]['index'])
                    for resource_file_value in resource_file_root.iter():
                        if resource_file_value.tag == "item" and "name" in resource_file_value.attrib.keys():
                            resource_idx_by_name["item"][resource_file_value.attrib["name"]] = res_idx
                            if "attr" in resource_idx_by_name.keys():
                                if resource_file_value.attrib["name"] in resource_idx_by_name["attr"].keys():
                                    target = resource_idx_by_name["attr"][resource_file_value.attrib["name"]]
                                    resource_dict[target[0]]["reachable"] = resource_dict[target[0]]["reachable"] + [res_idx[1]]
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [target[1]]
                            if "id" in resource_idx_by_name.keys():
                                if resource_file_value.attrib["name"] in resource_idx_by_name["id"].keys():
                                    target = resource_idx_by_name["id"][resource_file_value.attrib["name"]]
                                    resource_dict[target[0]]["reachable"] = resource_dict[target[0]]["reachable"] + [res_idx[1]]
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [target[1]]
                        if type(resource_file_value.text) == str and style_ref.match(resource_file_value.text):
                            resource_file_value_text = resource_file_value.text.replace("?","")
                            resource_file_value_text = resource_file_value_text.split('}')[-1]
                            resource_file_value_text = resource_file_value_text.split(':')[-1]
                            ref_idx = None
                            if len(resource_file_value_text.split("/")) > 1:
                                if resource_file_value_text.split("/")[0] in resource_idx_by_name.keys():
                                    if resource_file_value_text.split("/")[1] in resource_idx_by_name[resource_file_value_text.split("/")[0]].keys():
                                        ref_idx = resource_idx_by_name[resource_file_value_text.split("/")[0]][resource_file_value_text.split("/")[1]]
                            else: 
                                if "attr" in resource_idx_by_name.keys():
                                    if resource_file_value_text.split("/")[-1] in resource_idx_by_name["attr"].keys():
                                        ref_idx = resource_file_value_text["attr"][resource_file_value_text.split("/")[-1]]
                                else:
                                    if resource_file_value_text.split("/")[-1] in resource_idx_by_name["item"].keys():
                                        ref_idx = resource_idx_by_name["item"][resource_file_value_text.split("/")[-1]]
                            if ref_idx:
                                resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]

                        if type(resource_file_value.text) == str and resource_ref.match(resource_file_value.text):
                            resource_file_value_text = resource_file_value.text.replace("@","")
                            resource_file_value_text = resource_file_value_text.split('}')[-1]
                            resource_file_value_text = resource_file_value_text.split(':')[-1]
                            ref_idx = None
                            if resource_file_value_text.split("/")[0] in resource_idx_by_name.keys():
                                if resource_file_value_text.split("/")[1] in resource_idx_by_name[resource_file_value_text.split("/")[0]].keys():
                                    ref_idx = resource_idx_by_name[resource_file_value_text.split("/")[0]][resource_file_value_text.split("/")[1]]
                            if ref_idx:
                                resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]


                        for resource_file_attrib_key, resource_file_attrib_val in resource_file_value.attrib.items():
                            if not android_res in resource_file_attrib_key:
                                ref_idx = None
                                if "attr" in resource_idx_by_name.keys():
                                    if resource_file_attrib_key.split("}")[-1] in resource_idx_by_name["attr"].keys():
                                        ref_idx = resource_idx_by_name["attr"][resource_file_attrib_key.split("}")[-1]]
                                else:
                                    if resource_file_attrib_key.split("}")[-1] in resource_idx_by_name["item"].keys():
                                        ref_idx = resource_idx_by_name["item"][resource_file_attrib_key.split("}")[-1]]
                                if ref_idx:
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                            if style_ref.match(resource_file_attrib_val):
                                resource_file_attrib_val = resource_file_attrib_val.replace("?","")
                                resource_file_attrib_val = resource_file_attrib_val.split('}')[-1]
                                resource_file_attrib_val = resource_file_attrib_val.split(':')[-1]
                                ref_idx = None
                                if len(resource_file_attrib_val.split("/")) > 1:
                                    if resource_file_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                                        if resource_file_attrib_val.split("/")[1] in resource_idx_by_name[resource_file_attrib_val.split("/")[0]].keys():
                                            ref_idx = resource_idx_by_name[resource_file_attrib_val.split("/")[0]][resource_file_attrib_val.split("/")[1]]
                                else: 
                                    if "attr" in resource_idx_by_name.keys():
                                        if resource_file_attrib_val.split("/")[-1] in resource_idx_by_name["attr"].keys():
                                            ref_idx = resource_idx_by_name["attr"][resource_file_attrib_val.split("/")[-1]]
                                    else:
                                        if resource_file_attrib_val.split("/")[-1] in resource_idx_by_name["item"].keys():
                                            ref_idx = resource_idx_by_name["item"][resource_file_attrib_val.split("/")[-1]]
                                if ref_idx:
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                            if resource_ref.match(resource_file_attrib_val):
                                resource_file_attrib_val = resource_file_attrib_val.replace("@","")
                                resource_file_attrib_val = resource_file_attrib_val.split('}')[-1]
                                resource_file_attrib_val = resource_file_attrib_val.split(':')[-1]
                                ref_idx = None
                                if resource_file_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                                    if resource_file_attrib_val.split("/")[1] in resource_idx_by_name[resource_file_attrib_val.split("/")[0]].keys():
                                        ref_idx = resource_idx_by_name[resource_file_attrib_val.split("/")[0]][resource_file_attrib_val.split("/")[1]]
                                if ref_idx:
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]

                        # Searching Access and Reference in value, attributes of child elements
                        # We assume that there is no child element depth of 2
                        for resource_file_value_item in resource_file_value.iter():
                            if resource_file_value_item.tag == "item" and "name" in resource_file_value_item.attrib.keys():
                                resource_idx_by_name["item"][resource_file_value_item.attrib["name"]] = res_idx
                                if "attr" in resource_idx_by_name.keys():
                                    if resource_file_value_item.attrib["name"] in resource_idx_by_name["attr"].keys():
                                        target = resource_idx_by_name["attr"][resource_file_value_item.attrib["name"]]
                                        resource_dict[target[0]]["reachable"] = resource_dict[target[0]]["reachable"] + [res_idx[1]]
                                        resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [target[1]]
                                if "id" in resource_idx_by_name.keys():
                                    if resource_file_value_item.attrib["name"] in resource_idx_by_name["id"].keys():
                                        target = resource_idx_by_name["id"][resource_file_value_item.attrib["name"]]
                                        resource_dict[target[0]]["reachable"] = resource_dict[target[0]]["reachable"] + [res_idx[1]]
                                        resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [target[1]]
                            if type(resource_file_value_item.text) == str and style_ref.match(resource_file_value_item.text):
                                resource_file_value_item_text = resource_file_value_item.text.replace("?","")
                                resource_file_value_item_text = resource_file_value_item_text.split('}')[-1]
                                resource_file_value_item_text = resource_file_value_item_text.split(':')[-1]
                                ref_idx = None
                                if len(resource_file_value_item_text.split("/")) > 1:
                                    if resource_file_value_item_text.split("/")[0] in resource_idx_by_name.keys():
                                        if resource_file_value_item_text.split("/")[1] in resource_idx_by_name[resource_file_value_item_text.split("/")[0]].keys():
                                            ref_idx = resource_idx_by_name[resource_file_value_item_text.split("/")[0]][resource_file_value_item_text.split("/")[1]]
                                else: 
                                    if "attr" in resource_idx_by_name.keys():
                                        if resource_file_value_item_text.split("/")[-1] in resource_idx_by_name["attr"].keys():
                                            ref_idx = resource_idx_by_name["attr"][resource_file_value_item_text.split("/")[-1]]
                                    else:
                                        if resource_file_value_item_text.split("/")[-1] in resource_idx_by_name["item"].keys():
                                            ref_idx = resource_idx_by_name["item"][resource_file_value_item_text.split("/")[-1]]
                                if ref_idx:
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                            if type(resource_file_value_item.text) == str and resource_ref.match(resource_file_value_item.text):
                                resource_file_value_item_text = resource_file_value_item.text.replace("@","")
                                resource_file_value_item_text = resource_file_value_item_text.split('}')[-1]
                                ref_idx = None
                                if resource_file_value_item_text.split("/")[0] in resource_idx_by_name.keys():
                                    if resource_file_value_item_text.split("/")[1] in resource_idx_by_name[resource_file_value_item_text.split("/")[0]].keys():
                                        ref_idx = resource_idx_by_name[resource_file_value_item_text.split("/")[0]][resource_file_value_item_text.split("/")[1]]
                                if ref_idx:
                                    resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                                
                            for resource_file_item_attrib_key, resource_file_item_attrib_val in resource_file_value_item.attrib.items():
                                if not android_res in resource_file_item_attrib_key:
                                    ref_idx = None
                                    if "attr" in resource_idx_by_name.keys():
                                        if resource_file_item_attrib_key.split("}")[-1] in resource_idx_by_name["attr"].keys():
                                            ref_idx = resource_idx_by_name["attr"][resource_file_item_attrib_key.split("}")[-1]]
                                    else:
                                        if resource_file_item_attrib_key.split("}")[-1] in resource_idx_by_name["item"].keys():
                                            ref_idx = resource_idx_by_name["item"][resource_file_item_attrib_key.split("}")[-1]]
                                    if ref_idx:
                                        resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                                if style_ref.match(resource_file_item_attrib_val):
                                    resource_file_item_attrib_val = resource_file_item_attrib_val.replace("?","")
                                    resource_file_item_attrib_val = resource_file_item_attrib_val.split('}')[-1]
                                    resource_file_item_attrib_val = resource_file_item_attrib_val.split(':')[-1]
                                    ref_idx = None
                                    if len(resource_file_item_attrib_val.split("/")) > 1:
                                        if resource_file_item_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                                            if resource_file_item_attrib_val.split("/")[1] in resource_idx_by_name[resource_file_item_attrib_val.split("/")[0]].keys():
                                                ref_idx = resource_idx_by_name[resource_file_item_attrib_val.split("/")[0]][resource_file_item_attrib_val.split("/")[1]]
                                    else: 
                                        if "attr" in resource_idx_by_name.keys():
                                            if resource_file_item_attrib_val.split("/")[-1] in resource_idx_by_name["attr"].keys():
                                                ref_idx = resource_idx_by_name["attr"][resource_file_item_attrib_val.split("/")[-1]]
                                        else:
                                            if resource_file_item_attrib_val.split("/")[-1] in resource_idx_by_name["item"].keys():
                                                ref_idx = resource_idx_by_name["item"][resource_file_item_attrib_val.split("/")[-1]]
                                    if ref_idx:
                                        resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]
                                if resource_ref.match(resource_file_item_attrib_val):
                                    resource_file_item_attrib_val = resource_file_item_attrib_val.replace("@","")
                                    resource_file_item_attrib_val = resource_file_item_attrib_val.split('}')[-1]
                                    resource_file_item_attrib_val = resource_file_item_attrib_val.split(':')[-1]
                                    ref_idx = None
                                    if resource_file_item_attrib_val.split("/")[0] in resource_idx_by_name.keys():
                                        if resource_file_item_attrib_val.split("/")[1] in resource_idx_by_name[resource_file_item_attrib_val.split("/")[0]].keys():
                                            ref_idx = resource_idx_by_name[resource_file_item_attrib_val.split("/")[0]][resource_file_item_attrib_val.split("/")[1]]
                                    if ref_idx:
                                        resource_dict[res_idx[0]]["reachable"] = resource_dict[res_idx[0]]["reachable"] + [ref_idx[1]]

                        resource_dict[res_idx[0]]["reachable"] = list(set(resource_dict[res_idx[0]]["reachable"]))
    return resource_dict, resource_idx_by_name

def update_resource_processed(resource_dict, resource_type, resource_name, update_processed):
    for key, val in resource_dict.items():
        if val["type"] == resource_type and val["name"] == resource_name:
            resource_dict[key]["processed"] = resource_dict[key]["processed"] + [update_processed]

def update_resource_size(resource_dict, resource_type, resource_name, update_size):
    for key, val in resource_dict.items():
        if val["type"] == resource_type and val["name"] == resource_name:
            resource_dict[key]["size"] = update_size

def update_resource_child(resource_dict, resource_type, resource_name, update_child):
    for key, val in resource_dict.items():
        if val["type"] == resource_type and val["name"] == resource_name:
            resource_dict[key]["child"] = update_child

def get_resource_info_by_name(resource_dict, resource_type, resource_name):
    for key, val in resource_dict.items():
        if val["type"] == resource_type and val["name"] == resource_name:
            return resource_dict[key]
    return {"type":"", "name":"", "size":0, "index":-1, "child": [], "processed": []}

print "Welcome to Instant-slicer!"

if args.percent and args.byte:
    sys.exit("Percent and byte option should not be set at the same time!")

if args.percent:
    APK_SIZE_LIMIT = int(get_original_apk_size(args.target_path[0]) * float(args.percent))
if args.byte:
    APK_SIZE_LIMIT = int(args.byte)
DEMO_SIZE_LIMIT = APK_SIZE_LIMIT

start_time = time.time()
print "Unpacking target application at : "+TEMP_PATH
DEMO_SIZE_LIMIT_R = unpack_target(args.target_path[0])
print "Current APK Limit : "+str(APK_SIZE_LIMIT)
print "Original APK Size : "+str(get_original_apk_size(args.target_path[0]))
print "Unpacked Size : "+str(DEMO_SIZE_LIMIT_R)


print "Parsing resource list from XML ..."
resource_dict, resource_idx_by_name = get_resource_dict()
#resource_dict = {}

print "Parsing asset list from directory ..."
asset_dict = get_asset_dict(resource_dict)

print "Calculate resource dependency from XML ..."
resource_dict, resource_idx_by_name = calculate_resource_size(resource_dict, asset_dict, resource_idx_by_name)

parse_time = time.time()

print "Resource Parse : "+str(parse_time-start_time)

asset_time = time.time()

print "Calculating resource size weighted method dependency graph ..."
costs, edges, vertices, methods, classes = build_method_dependency_graph(args.ec_file_path[0], args.pickle_path[0], resource_dict, asset_dict)
edges = list(set(edges))

encode_time = time.time()

print "Encoding Time : "+str(encode_time-asset_time)

print "Parsing AndroidManifest for initial resource usage check ..."
init_resources = parseAndroidManifest(resource_dict, resource_idx_by_name)

sav_model = None
ilp_vertices = None
ilp_resources = None

while SEARCH_DEPTH > 0:
    if args.merge:
        print "Merging Drawables ..."
        merge_drawables()
        print "Merging Mipmaps ..."
        merge_mipmaps()
    ilp_start_time = time.time()
    print "Solving Maximum Code Coverage Problem ..."
    ilp_vertices, ilp_resources, sav_model = solve_ilp(costs, edges, vertices, methods, init_resources, resource_dict, sav_model)
    ilp_end_time = time.time()
    print "ILP Time (One Time) : "+str(ilp_end_time-ilp_start_time)
    if ilp_vertices != None and ilp_resources != None:
        all_vertices_len = 0;
        covered_len = 0;
        for a in ilp_vertices:
            if a == 1:
                covered_len = covered_len + 1
            all_vertices_len = all_vertices_len + 1
        print "Covered :" + str(covered_len) + "/" + str(all_vertices_len)
    else:
        SEARCH_DEPTH = SEARCH_DEPTH - 1
        DEMO_SIZE_LIMIT_L = DEMO_SIZE_LIMIT
        DEMO_SIZE_LIMIT = int((DEMO_SIZE_LIMIT + DEMO_SIZE_LIMIT_R) / 2)
        print "Search Size at "+str(DEMO_SIZE_LIMIT_L)+" is INFEASIBLE. Search size moves to "+str(DEMO_SIZE_LIMIT)+" ("+str(SEARCH_DEPTH)+" Trial left)"
        continue

    #print ilp_resources[get_resource_info_by_name(resource_dict, "drawable", "flag_circle_deu")['index']]
    total_ilp_time = time.time()

    print "ILP Time (Total) : "+str(total_ilp_time-encode_time)

    # Debug code (Check If there is undecided resource element)
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
    generate_smali_code(ilp_vertices, classes, methods)

    if args.purge_res:
        print "Deleting Unused Resources ..."

        # Not purging xml resources
        '''
        change = purge_assets(asset_dict, ilp_resources)
        print str(change) + " resources deleted."

        '''

        change = 1
        while change > 0:
            change = 1
            change = change + purge_resources(resource_dict, asset_dict, ilp_resources)
            change = change + purge_assets(asset_dict, ilp_resources)
            print str(change-1) + " resources deleted."
            change = change - 1

    print "Deleting Duplicated Files ..."
    remove_duplicated_files()
    print "Repackaging into APK ..."
    package_size_cond = repack(args.output)

    if SEARCH_DEPTH == 0:
        break
    elif package_size_cond == 1:
        DEMO_SIZE_LIMIT_SUCCESS = DEMO_SIZE_LIMIT
        DEMO_SIZE_LIMIT_L = DEMO_SIZE_LIMIT

        # Copy successful apk.
        outdir = args.output
        if not outdir:
            outdir = TEMP_PATH + "/../"
        FNULL = open(os.devnull, 'w')
    
        copy_success_apk_process = subprocess.call("cp "+outdir+"reduced_temp_"+str(dupchecker)+".apk "+outdir+"reduced_app_"+str(DEMO_SIZE_LIMIT_SUCCESS)+".apk", shell=True, stdout=FNULL)

        DEMO_SIZE_LIMIT = int((DEMO_SIZE_LIMIT + DEMO_SIZE_LIMIT_R) / 2)
        print "Search Size at "+str(DEMO_SIZE_LIMIT_R)+" is FEASIBLE. Search size moves to "+str(DEMO_SIZE_LIMIT)+" ("+str(SEARCH_DEPTH)+" Trial left)"
    else:
        SEARCH_DEPTH = SEARCH_DEPTH - 1
        DEMO_SIZE_LIMIT_R = DEMO_SIZE_LIMIT
        DEMO_SIZE_LIMIT = int((DEMO_SIZE_LIMIT + DEMO_SIZE_LIMIT_L) / 2)
        print "Search Size at "+str(DEMO_SIZE_LIMIT_L)+" is INFEASIBLE. Search size moves to "+str(DEMO_SIZE_LIMIT)+" ("+str(SEARCH_DEPTH)+" Trial left)"

    print "Rebase to original files ..."
    resetToOriginal()

if args.clean:
    print "Cleaning up all the mess ..."
    cleanup()

if DEMO_SIZE_LIMIT_SUCCESS != 0:
    print "Demo Generation is successful! Your demo app size is : "+str(DEMO_SIZE_LIMIT_SUCCESS)
else:
    print "Demo Generation is failed. Please adjust your demo app size limit."
end_time = time.time()
time_ellipsed = end_time - start_time
print "ellipsed time : "+str(time_ellipsed)+" sec"

