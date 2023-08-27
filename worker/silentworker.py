# Copyright 2022 by Minh Nguyen. All rights reserved.
#     @author Minh Tu Nguyen
#     @email  nmtu.mia@gmail.com
# 
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from worker.base.silentworker_base import SilentWorkerBase
from utils.utils import log
import r2pipe
import os
import re


class SilentWorker(SilentWorkerBase):
    """
    This is the baseline for the SilentWorker.

    SilentWorker should be the one carrying the main work.
    Sometimes a module might take a great deal of time to generate outputs. 

    Whenever your model finishes an operation, make sure to call `__onFinish__` function to populate your results to db as well as to the next module in the chain.
        Command:
            self.__onFinish__(output[, note])

        whereas:
            - output (mandatory): A dict that maps a `orig_input_hash` => output
                Output could be of any type. Just make sure to note that in your module's configuration and description for others to interpret your results.
                For example,
                    - a detector module can return a boolean (to represent detection result).
                    - a non-detector module (eg. processor or sandbox) can return the path storing processed result.
                eg.
                    {
                        'hash_of_input_1': true,
                        'hash_of_input_2': false,
                        'hash_of_input_3': false,
                        ...
                    }
            - note (optional).
                It could be a dict or a string.
                If it's a dict, it must be a map of a filepath to a note (string). The system will find and save the note accordingly with the file. 
                If it's not a map, use a string. The system will save this note for all the files analyzed in this batch
    """

    def __init__(self, config) -> None:
        """ Dont change/remove this super().__init__ line.
            This line passes config to initialize services. 
        """
        super().__init__(config)

        #! Add your parts of initializing the model or anything you want here. 
        #! You might want to load everything at this init phase, not reconstructing everything at each request (which shall then be defined in run())
        self.clean_pattern = re.compile(r'(.*)(\||\│|\╎|\└|\\|\<|\>)\s(.*)')
        self.replace_var_pattern = re.compile(r'((0x|fcn\.|arg\_|var\_)([0-9a-z]{1,8}))')

        self.dir__asm_raw = '' #! will update at every time calling disasm function, in case module_outdir is changed
        self.dir__asm_cleaned = '' #! will update at every time calling disasm function, in case module_outdir is changed

        self.create_out_dirs()

    
    def onChangeConfig(self, config_data):
        """
        Callback function when module's config is changed.
        (usually at each request to analyze, when config_data is sent along as a parameter)
        ---
        This is the module's config which is passed at each analysis request. (usually the config to initialize the model)
        """

        log(f'[ ][SilentWorker][onChangeConfig] config_data is passed: {config_data}')

        #! Want to do something with the model when the config is changed ? Maybe reconfig the model's params, batch size etc. ?
        #? eg. change global module's config
        #self._config = config_data
        
        return

    
    def create_out_dirs(self):
        if not os.path.isdir(self.module_outdir):
            log(f'[x][SilentWorker][create_out_dirs] modules_outdir {self.module_outdir} not exist', 'error')
            return False
        
        try:
            self.dir__asm_raw = f'{self.module_outdir}/asm_raw'
            self.dir__asm_cleaned = f'{self.module_outdir}/asm_cleaned'
            self.dir__cfg = f'{self.module_outdir}/cfg'

            if not os.path.isdir(self.dir__asm_raw):
                os.makedirs(self.dir__asm_raw)
            if not os.path.isdir(self.dir__asm_cleaned):
                os.makedirs(self.dir__asm_cleaned)
            if not os.path.isdir(self.dir__cfg):
                os.makedirs(self.dir__cfg)
                
            return True
        except:
            log(f'[x][SilentWorker][create_out_dirs] errors while creating {self.dir__asm_raw} or {self.dir__asm_cleaned} or {self.dir__cfg}', 'error')
            return False


    def disasm(self, filepath):
        has_outdir = self.create_out_dirs()
        if has_outdir is False:
            return None, None

        filename = os.path.basename(filepath)

        r = r2pipe.open(filepath)
        # log(f'[SilentWorker][disasm] [ ]   asm_raw : {asm_raw}')
        log('>> aaa')
        r.cmd('aaa')
        log('>> agC > dot/{}/{}.dot'.format(self.dir__cfg, filename))
        og = r.cmd('agC > dot/{}/{}.dot'.format(self.dir__cfg, filename))
        log('>> agC > ... = ', og)

        log('>> pd')
        asm_raw = r.cmd('pd')

        od = asm_raw.split('\n')

        #? clean
        cleaned = []
        for line in od:
            # line = ' '.join((line).split()).strip()
            line = line.strip()
            log(f'[Asm_Module][disasm] line: "{line}"')
            
            if len(line) == 0:
                continue

            if line[0] not in ['/', ';']:
                m = self.clean_pattern.search(line)
                if m:
                    lin = m.group(3)
                else:
                    lin = line
                if lin[0] not in ['-', ';', '┌']:
                    lin = lin.split(';')[0]

                    if lin[:2] == '0x':
                        spl = lin.split(' ')
                        lin = ' '.join(spl[2:])

                    cleaned.append(lin)

        #? replace var
        final = []
        for line in cleaned:
            s = ' '.join((line).split()).strip().replace('int3', 'int')

            for x in re.finditer(self.replace_var_pattern, s):
                s = s.replace(x.group(), 'var')

            final.append(s)

        asm_cleaned = ' . '.join(final)

        log('[+][SilentWorker][disasm] [+]   Done')

        return asm_raw, asm_cleaned


    def infer(self, config_data):
        """
        #? This function is to be overwritten.
        Main `inference` function. 

            #? (used for all modules, `detector`, `(pre)processor`, `sandbox`)
            Whatever you need to do in silence, put it here.
            We provide inference in batch, for heavy models.

        ----
        Use these vars to access input data:
            - self._map_ohash_inputs: dict of inputs to feed this module (eg. filepath to the executable files already stored on the system / url).
                map `orig_input_hash` => `prev module's output for orig_path correspond with orig_input_hash`
            - self._map_ohash_oinputs: dict of original inputs that is fed to this module flow.
                map `orig_input_hash` => one `orig_path`.
                (multiple orig_path might have the same hash, but just map to one path)
        
        Params:
            - config_data: modules configuration stored in the db.
        """

        #! Do something
        log('[ ][SilentWorker][infer] I\'m pretty')

        result = {}
        for orig_filehash, filepath in self._map_ohash_inputs.items():
            filename = os.path.basename(filepath)

            log(f'[SilentWorker][infer] [ ] Processing {filepath}')

            if not os.path.isfile(filepath):
                log(f'[SilentWorker][infer] [x] {filepath} not found')
                continue

            # r = r2pipe.open(filepath)
            # log('\t aaa')
            # r.cmd('aaa')
            # log('\t agC > dot/{}/{}.dot'.format(dirname, file))
            # og = r.cmd('agC > dot/{}/{}.dot'.format(dirname, file))
            # log('\t agC', og)

            asm_raw, asm_cleaned = self.disasm(filepath)

            if asm_raw is None or asm_cleaned is None:
                log(f'[SilentWorker][infer] [x] {asm_raw} or {asm_cleaned} is None')
                continue
                
            open(f'{self.dir__asm_raw}/{filename}.asm', 'w').write(asm_raw)
            open(f'{self.dir__asm_cleaned}/{filename}.asm', 'w').write(asm_cleaned)

            #? add to result dict
            result[orig_filehash] = [f'{self.dir__asm_cleaned}/{filename}.asm', f'{self.dir__cfg}/{filename}.jpg', f'{self.dir__cfg}/{filename}.dot']

            
        #! Call __onFinishInfer__ when the analysis is done. This can be called from anywhere in your code. In case you need synchronous processing
        self.__onFinishInfer__(result)
