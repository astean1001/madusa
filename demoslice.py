import os
import re
import pulp
import argparse

import xml.etree.ElementTree as ET
import acvtool.smiler.reporter as ACV

TEMP_PATH = '~/demoslice/temp'

parser = argparse.ArgumentParser(description='Slicing and repackaging Android APK into demo application based on demo scenario.')
parser.add_argument('target_path', metavar='target', type=str, nargs=1,
                    help='Path to target android application.')
parser.add_argument('ec_file_path', metavar='ec_files', type=str, nargs=1,
                    help='Path to EC files.')
parser.add_argument('pickle_path', metavar='pickle', type=str, nargs=1,
                    help='Path to pickle object.')
parser.add_argument('--output', '-o' action='store',
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
	asset_path = TEMP_PATH + "assets/"

	for dirpath, dirnames, filenames in os.walk(asset_path):
		try:
			_asset_dict[os.path.join(dirpath,filename)] = os.path.getsize(os.path.join(dirpath,filename))
		except OSError:
			raise Exception('Asset File Size Fetching Failed : Check permission settings on your home folder.')

	return _asset_dict

def build_method_dependency_graph(ec_files, pickle, resource_dict, asset_list):
    ec_files = [os.path.join(ec_dir, f) for f in os.listdir(ec_dir) if os.path.isfile(os.path.join(ec_dir, f))]
    smalitree = ACV.get_covered_smalitree(ec_files, pickle)

    _node_list = []
    _edge_list = []

    # connect invokes
    for cl in smalitree.classes:
    	for m in cl.methods:

def solve_ilp():
	model = pulp.LpProblem("Coverage Maximizing Problem", pulp.LpMaximize)

def generate_smali_code():
	pass

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