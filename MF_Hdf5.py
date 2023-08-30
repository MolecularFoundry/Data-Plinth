from datetime import datetime
from pathlib import Path

#from pyscicat.client import from_token
#from pyscicat.model import Ownable, RawDataset
import os
import h5py
import json
import numpy as np

#this class takes an object and encodes it to a JSON readable version of it
class ScopeFoundryJSONEncoder(json.JSONEncoder):
    def default(self, h5File):
        #below are the following special cases. More can be added if there
        #other strange data types within the h5
        if isinstance(h5File, np.bool_):
            return bool(h5File)
        if isinstance(h5File, np.int32):
            return int(h5File)
        if isinstance(h5File, np.int64):
            return int(h5File)
        if isinstance(h5File, np.ndarray):
            return h5File.tolist()
        # Let the base class default method raise the TypeError
        return json.JSONEncoder.default(self, h5File)

#open a h5 file for reading

#This is the line of code to change
#modify for separate application in gigapixel surveyor
class MF_Hdf5_Decoder:

    def __init__(self,h5File):
        self.h5FilePath = h5File.filename
        self.h5File = h5File
        self.meta = dict(path='')
        self.dataset_include = [
            'measurement/hyperspec_picam_mcl/imshow_extent', 
            'measurement/hyperspec_picam_mcl/corners',
            'measurement/hyperspec_picam_mcl/range_extent',
            ]

    def dumps(self):
        return json.dumps(self.meta, indent=4, cls=ScopeFoundryJSONEncoder)
    def decode(self,path, obj):
        parent = self.meta
        #print (self.h5FilePath, self.h5File)
        # This version makes a hirearchy
        #print("#"*80)
        #print(self.h5FilePath, self.h5FilePath.split('/'))
        path_parts = self.h5FilePath.split('/') 
        for depthIndex,pathIndex in enumerate(path_parts):
            #print("depth",depthIndex,pathIndex, parent)
            if not pathIndex in parent.keys():
                #print("making ", self.h5FilePath, pathIndex)
                parent[path] = {
                    'path': parent['path'] + "/" + path
                }
            else:

                print("exists ", self.h5FilePath, path, parent[path])
        parent = parent[path]
        currentDepthList = parent
        ##print('', parent)

        if isinstance(obj, h5py.Group):
            #print("asdf", self.h5File, path)
            for k,v in obj.attrs.items():
                #print(k,v,type(v))
                currentDepthList[k] = v
        if isinstance(obj, h5py.Dataset):
            currentDepthList.update({
                    'type': 'Dataset',
                    'shape': obj.shape,
                    'dtype': str(obj.dtype),
                    'chunks': obj.chunks
                })
            if path in self.dataset_include:
                currentDepthList['data'] = np.array(obj).tolist()
if __name__ == "__main__":
    if len(sys.argv) > 1:
        mfF5Decoder = MF_Hdf5_Decoder(h5File().File(sys.argv[1]))
        mfF5Decoder.h5File.visititems(mfF5Decoder.decode)
        mfF5Decoder.dump()
    else:
        print("please provide filename for H5File")