import json 
import os 
import ast 
import sys
import inspect
import glob 
import astor
import shutil



def process_func_dict(func_dict):
    
    
    return {k: list(set(v)) for k, v in func_dict.items()}


def get_function_code(source_code, function_name):
    tree = ast.parse(source_code)
    
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == function_name:
            start_line = node.lineno
            end_line = node.end_lineno
            result = "\n".join(source_code.split('\n')[start_line - 1:end_line])
            return result
    
    return ""  # Function not found

def collect_calls(source): 
    calls = []
    class Visitor(ast.NodeVisitor):
        def visit_Call(self, node):
            if isinstance(node, ast.Call): 
                # print(node.func, ast.unparse(node) , ast.unparse(node.func))
                # input('ok ?')
                calls.append(ast.unparse(node.func))
            self.generic_visit(node)
    tree = ast.parse(source)
    visitor = Visitor()
    visitor.visit(tree)
    return calls


def base_id_func(source_code: str, 
                 target_modules : list, 
                 return_local : bool = False):
    local_funcs = []
    funcs_per_module = {}
    # COLLECTS LOCAL FUNCTIONS
    class ScriptVisitor(ast.NodeVisitor):     
        def visit_FunctionDef(self, node: ast.FunctionDef): 
            local_funcs.append(node.name)
            self.generic_visit(node)
    
    # COLLECTS FUNCTIONS FROM TARGET MODULES 
    class ScriptVisitor2(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id in target_modules:
                        if node.func.value.id not in funcs_per_module.keys():
                            funcs_per_module[node.func.value.id] = []
                        funcs_per_module[node.func.value.id].append(node.func.attr)                             

            self.generic_visit(node)

    tree = ast.parse(source_code)
    visitor = ScriptVisitor()
    visitor.visit(tree)
    visitor2 = ScriptVisitor2()
    visitor2.visit(tree)
    if return_local: 
        return process_func_dict(funcs_per_module), local_funcs
    return process_func_dict(funcs_per_module)
    

def run_local_check(target_script_path):

    local_python_files= glob.glob(os.path.join(os.path.dirname(target_script_path), '*.py'))
    local_libs = [os.path.basename(f).replace('.py', '') for f in local_python_files]
    to_carry_over = [] 

    class ImportFinder(ast.NodeVisitor):
        def visit_Import(self, node): 
            for alias in node.names: 
                valid = False
                if alias.asname: 
                    if alias.asname in local_libs: 
                        valid = True 
                else: 
                    if alias.name in local_libs: 
                        valid = True
                if valid: 
                    to_carry_over.append(os.path.join(os.path.dirname(target_script_path), alias.name + '.py'))

        def visit_ImportFrom(self, node): 
            for alias in node.names: 
                valid = False
                if alias.asname: 
                    if alias.asname in local_libs: 
                        valid = True 
                else: 
                    if alias.name in local_libs: 
                        valid = True
                if valid: 
                    to_carry_over.append(os.path.join(os.path.dirname(target_script_path), alias.name + '.py'))
    ImportFinder().visit(ast.parse(open(target_script_path).read()))

    return to_carry_over


def run_vacuum(target_script_path = "/home/mehdimounsif/Codes/Tests/run_flows/exploitation_auto_rsa.py",
               target_modules = ['mome', 'momeutils', 'mcodeutils', 'magents', 'flowme'], 
               base_lib_path = '/home/mehdimounsif/Codes/my_libs/m2me', 
               ouput_file = os.path.join(os.path.dirname(__file__), 'results_vacuum.json')): 
    
    def process_function(module_name, func_name, left_to_visit, visited):
            if func_name in visited[module_name]:
                return
            
            visited[module_name].append(func_name)
            
            module_source = open(os.path.join(base_lib_path, module_name + '.py')).read()
            _, local = base_id_func(module_source, [], return_local=True)
            # print("Processing function", module_name, func_name)
            additional_local_calls = collect_calls(get_function_code(module_source, func_name))
            additional_local_calls = {module_name: [a for a in additional_local_calls if a in local]}
            external_calls = base_id_func(get_function_code(module_source, func_name), target_modules)
            
            for ke in external_calls.keys():
                for kev in external_calls[ke]:
                    if kev not in left_to_visit[ke]:
                        left_to_visit[ke].append(kev)
            
            for local_func in additional_local_calls[module_name]:
                if local_func not in visited[module_name]:
                    process_function(module_name, local_func, left_to_visit, visited)
        
    fd = base_id_func(open(target_script_path).read(), target_modules)
    left_to_visit = {k: [] for k in target_modules}
    visited = {k: [] for k in target_modules}
    
    for k in fd.keys():
        for func in fd[k]:
            print('Processing', k, func)
            process_function(k, func, left_to_visit, visited)

    # print(json.dumps(left_to_visit, indent=4))   
    # input(' ok 0 ? ')
    for k in left_to_visit.keys():
        for func in left_to_visit[k]:
            process_function(k, func, left_to_visit, visited)    

    # ARE SOME ADDITIONAL LOCAL FILES USED ? 
    files_to_carry_over = run_local_check(target_script_path)
    

    # TMP !!!!! 
    # results = {"translation_params":
    #            {"output_libs_folder": "/home/mehdimounsif/Codes/my_libs/sample_test", 
    #             "lib_names": {k:k.replace('test_utils', 'base_sode_utils').replace('mcodeutils', 'sode_code_utils').replace('mome', "initial_mome") for k in target_modules if (k in visited.keys() and len(visited[k]) > 0 )},
    #             "base_lib_path": base_lib_path, 
    #             "initial_script" : target_script_path, 
    #             "output_script_name" : "sample_main.py", 
    #             "files_to_carry_over" : files_to_carry_over}, 
    #            "required" : visited}
    # ======================================
    
    results = {"translation_params":
               {"output_libs_folder": "/home/mehdimounsif/Codes/my_libs/test_sode", 
                "lib_names": {k:k.replace('momeutils', 'base_sode_utils').replace('mcodeutils', 'sode_code_utils').replace('mome', "initial_mome") for k in target_modules if (k in visited.keys() and len(visited[k]) > 0 )},
                "base_lib_path": base_lib_path, 
                "initial_script" : target_script_path, 
                "output_script_name" : "sode_main.py", 
                "files_to_carry_over" : files_to_carry_over}, 
               "required" : visited}
    with open(ouput_file, 'w') as f:
        json.dump(results, f, indent=4)
    print('Results saved in', ouput_file)
    os.system('code ' + ouput_file)

def collect_code_from_module(source, functions):
    
    results = []
    imports = []
    imports_aliases = []
    useful_imports = []
    class ImportCollector(ast.NodeVisitor):

        def visit_Import(self, node): 
            imports.append(ast.unparse(node))
            for alias in node.names: 
                imports_aliases.append(alias.asname if alias.asname else alias.name)
            # imports.append(ast.unparse(node))
            self.generic_visit(node)
        def visit_ImportFrom(self, node): 
            imports.append(ast.unparse(node))
            for alias in node.names:    
                imports_aliases.append(alias.asname if alias.asname else alias.name)
            self.generic_visit(node)

    class UsefulImportsFounder(ast.NodeVisitor):

        def visit_Call(self, node): 
            if isinstance(node.func, ast.Attribute):
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id in imports_aliases:
                        useful_imports.append(node.func.value.id)
                        # for alias in imports_aliases: 
                        #         useful_imports.append(alias)

        
    for f in functions: 
        f_code = get_function_code(source, f)
        results.extend(f_code.split('\n'))
        results.append('\n')  
    
    tree = ast.parse(source)
    ImportCollector().visit(tree)
    UsefulImportsFounder().visit(tree)
    # print(imports)
    # print('\n\n')
    # input(list(set(useful_imports)))
    final_imports = []
    for i in imports: 
        if i.split(' ')[-1] in useful_imports: 
            final_imports.append(i)

    results = list(set(final_imports)) + [""]*2 + results
    # results = imports + results

    return "\n".join(results)



def run_string_check(collected_code, lib_names): 

    results = {k: [] for k in lib_names.keys()}
    for k in lib_names.keys(): 
        for i, l in enumerate(collected_code.split('\n')): 
            if k in l: 
                results[k].append({'line': i, 'content': l})
    
    return results

def glfn(code, node):  # get line from node
    
    start = node.lineno
    end = node.end_lineno

    return "\n".join(code.split('\n')[start - 1:end]).strip()

def process_collected_code(collected_code, config, debug = False): 

    changes_to_apply = []
    to_check  = []

    class ChangeNodeName(ast.NodeTransformer):

        def __init__(self, old_name, new_name): 
            self.old_name = old_name
            self.new_name = new_name

        def do_log(self, node):
            changes_to_apply.append({'initial': {"content" : glfn(collected_code, node), 'start' : node.lineno, 'end' : node.end_lineno, 'target' : self.old_name}, 'update': 'todo'})
                        
        def do_log_update(self, node, node_type):  
            changes_to_apply[-1]['update'] = {'node_type' : node_type, 'content': ast.unparse(node)}
        
        def visit_Import(self, node):
            for alias in node.names: 
                if alias.name == self.old_name: 
                    self.do_log(node)
                    alias.name = self.new_name
                    self.do_log_update(node, 'Import')
                    # if debug: 
                    #     print('Import', alias.name, self.new_name)
                        # input('o k ? ')

            return node
        
        def visit_ImportFrom(self, node): 
            for alias in node.names: 
                if alias.name == self.old_name: 
                    self.do_log(node)
                    alias.name = self.new_name
                    self.do_log_update(node, 'ImportFrom')
            return node
        
        def visit_Attribute(self, node):
            self.generic_visit(node)
            if isinstance(node.value, ast.Name) and node.value.id == self.old_name: 
                self.do_log(node)
                node.value.id = self.new_name
                self.do_log_update(node, 'Attribute')
                # changes_to_apply[-1].append([glfn(collected_code, node)])
            return node
        
        def visit_Name(self, node):
            if node.id == self.old_name: 
                self.do_log(node)
                node.id = self.new_name
                
                # go up to the highest node and unparse to recover full code --> then full line 
                self.do_log_update(node, 'Name')
                # if debug: 
                    # print('Name', node.id, self.new_name)
                    # input('ok ? ')
                # changes_to_apply[-1].append([glfn(collected_code, node)])
            return node
    
    updated_code = collected_code
    for k in config['translation_params']['lib_names'].keys(): 
        updated_code = ChangeNodeName(k, config['translation_params']['lib_names'][k]).visit(ast.parse(updated_code))
    

    # flatten the changes to apply
    # flattened_changes = []
    # for k in changes_to_apply.keys(): 
    #     flattened_changes.extend(changes_to_apply[k]['changes'])

    # sort the changes to apply based on the line number
    sorted_flattened_changes = sorted(changes_to_apply, key = lambda x: x['initial']['start'])
    
    # print(sorted_flattened_changes)
    # input('flattened above ?')

    # if debug: 
    #     print("\n".join(ast.unparse(updated_code).split('\n')[:30]))
    #     input(json.dumps(changes_to_apply, indent=4))
    
    # updated_code = ast.unparse(updated_code)

    updated_code = run_code_update(collected_code, sorted_flattened_changes)
    # if debug:
    #     print("\n".join(updated_code.split('\n')[:30]))
    #     input('Above for updated through run_code_update  ?')

    # updated_code = ast.unparse(ast.parse(updated_code)) # TMP !!!!! 
    to_check = run_string_check(updated_code, config['translation_params']['lib_names'])
    
    return updated_code, {'changes' : changes_to_apply, 'to_check' : to_check}

def run_code_update(code, changes_to_apply):

    new_code = []
    current_line = 0

    for change in changes_to_apply: 

        line_start = change['initial']['start']
        line_end = change['initial']['end']
        new_code.extend(code.split('\n')[current_line:line_start - 1])
        if change['update']['node_type'] == "Name": 
            # IDEALLY, THIS SHOULD BE DONE WITH AST
            initial_line = code.split('\n')[line_start - 1] 
            # print('inital content', change['initial']['content'], initial_line)
            # print('target', change['initial']['target'])
            # print('update', change['update']['content'])
            
            updated_line = initial_line.replace(change['initial']['target'], change['update']['content'])
            # input('there: ' + updated_line)
        elif change['update']['node_type'] == "Import": 
            updated_line = change['update']['content']
            # input('here: ' + updated_line)
        else: 
            raise ValueError('Node type {} not yet supported '.format(change['update']['node_type']))
        new_code.append(updated_line)
        current_line = line_end
    
    new_code.extend(code.split('\n')[current_line:])

        # input('\n'.join(new_code))

    return "\n".join(new_code)


def spit_out(translation_file = os.path.join(os.path.dirname(__file__), "results_vacuum.json")): 

    config = json.load(open(translation_file))

    if os.path.exists(config['translation_params']['output_libs_folder']):
        os.system('rm -r ' + config['translation_params']['output_libs_folder'])

    os.makedirs(config['translation_params']['output_libs_folder'])

    changes_log = {}
    for k in config['required'].keys(): 
        if len(config['required'][k]) > 0: 
            module_source = open(os.path.join(config['translation_params']['base_lib_path'], k + '.py')).read()
            collected_code = collect_code_from_module(module_source, config['required'][k]) 
            # input(collected_code)
            collected_code, change = process_collected_code(collected_code, config)
            # print(collected_code)
            # input("Processed {}".format(k))
            changes_log[k] = change
            p = os.path.join(config['translation_params']['output_libs_folder'], config['translation_params']['lib_names'][k] + '.py')
            # input(p)
            with open(p, 'w') as f: 
                f.write(collected_code)

    # copy pasting the files to carry over
    for f in config['translation_params']['files_to_carry_over']: 
        os.system('cp ' + f + ' ' + config['translation_params']['output_libs_folder'])

    # Processing the initial script 
    initial_script = open(config['translation_params']['initial_script']).read()
    # print("\n".join(initial_script.split('\n')[:50]))
    collected_code, change = process_collected_code(initial_script, config, debug = True)
    # input(json.dumps(change, indent = 4))
    input("\n".join(collected_code.split('\n')[:50]))
    changes_log['initial_script'] = change
    with open(os.path.join(config['translation_params']['output_libs_folder'], config['translation_params']['output_script_name']), 'w') as f: 
        f.write(collected_code)   



    with open(os.path.join(config['translation_params']['output_libs_folder'], 'changes_log.json'), 'w') as f:
        json.dump(changes_log, f, indent=4)
    
    configure_requirements(config)

def collect_default_pacakges(): 

    # Filter out the standard library paths
    python_vers = "python{major}.{minor}".format(major = sys.version_info.major, minor = sys.version_info.minor)
    std_lib_paths = [path for path in sys.path if ('site-packages' not in path and python_vers in path)]


    # List all modules in the standard library paths
    std_lib_modules = []
    for path in std_lib_paths:
        if os.path.isdir(path):
            std_lib_modules.extend([name.replace('.py', '') for name in os.listdir(path) if name.endswith('.py')])
    # print(std_lib_modules)
    return sorted(std_lib_modules)

def collect_libs_to_install(config):

    all_imports = []
    to_install = []
    class ImportCollector(ast.NodeVisitor): 
        def visit_Import(self, node): 
            for alias in node.names: 
                all_imports.append(alias.name)
            self.generic_visit(node)
    
    existing_libs = collect_default_pacakges()
    local_files = glob.glob(os.path.join(config['translation_params']['output_libs_folder'], '*.py'))
    
    for lib in local_files: 
        lib_name = os.path.basename(lib).replace('.py', '')
        if lib_name in config['translation_params']['lib_names'].keys():
            existing_libs.append(config['translation_params']['lib_names'][os.path.basename(lib).replace('.py', '')])
            existing_libs.extend(list(config['translation_params']['lib_names'].keys()))    
        else: 
            existing_libs.append(os.path.basename(lib).replace('.py', ''))
    # existing_libs += collect_default_pacakges()

    existing_libs = list(set(existing_libs))
        
    for f in local_files: 
        tree = ast.parse(open(f).read())
        ImportCollector().visit(tree)
    
    for i in list(set(all_imports)):
        if i not in existing_libs: 
            to_install.append(i)
    
    return to_install, local_files

def configure_requirements(config): 

    output_folder = config['translation_params']['output_libs_folder']

    to_install, local_files = collect_libs_to_install(config)
    
    # MAKE SETUP SCRIPT
    setup_script = """
from setuptools import setup, find_packages

setup(
    name = '{}', 
    version = '0.1',
    packages = find_packages(), 
    install_requires = [
    {}
    ], 
)
""".format(config['translation_params']['output_libs_folder'].split('/')[-1],
           ", \n\t".join(["'{}'".format(i) for i in to_install]))

    # MAKE INIT FILE

    init_file = "\nimport ".join([''] + [os.path.basename(lf).split('.')[0] for lf in local_files if os.path.basename(lf) != config['translation_params']['output_script_name']])

    with open(os.path.join(output_folder, 'setup.py'), 'w') as f: 
        f.write(setup_script)
    with open(os.path.join(output_folder, '__init__.py'), 'w') as f: 
        f.write(init_file)