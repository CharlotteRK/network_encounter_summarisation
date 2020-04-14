function[] = merge(folder, out_file)
    global mergedEv
    mergedEv = table('Size',[0 5],'VariableTypes',{'double','string','string', 'string', 'string'});
    mergedEnc = table('Size',[0 4],'VariableTypes',{'string','string', 'double', 'double'},'VariableNames',{'MAC1','MAC2','duration','frequency'});
    filesTxt = dir(fullfile(folder, '*.txt'));
    filesCsv = dir(fullfile(folder, '*.csv'));
    files = [filesCsv ; filesTxt];
    sz = size(files);
    if(sz(1) == 0)
        return;
    end
    for i = 1:sz(1)
        try
            pth = files(i).folder + "\" + files(i).name;
            raw = readtable(pth, "delimiter", " ");
            mergedEv = [mergedEv ; raw];

        catch
            try
                pth = files(i).folder + "\" + files(i).name;
                raw = readtable(pth, "delimiter", ",");
                mergedEnc = [mergedEnc ; raw];

            catch
                fprintf(2, "Error with merge input files. Incorrect delimiter or mismatched formats.\n");
                return;
            end
        end
    end
    szEnc = size(mergedEnc);
    szEv = size(mergedEv);
    if(szEnc(1) > szEv(1))
        mergedEnc = sortrows(mergedEnc);
        writetable(mergedEnc, out_file,'Delimiter',',');
    else
        mergedEv = sortrows(mergedEv);

        begin_time = mergedEv(1,1);
        mergedEv(:,1) = mergedEv(:,1) - begin_time;

        convert_ids()
        writetable(mergedEv, out_file,'Delimiter',' ',"WriteVariableNames",0);
    end
end


function convert_ids()
    global mergedEv
    sz = size(unique([mergedEv.id1;mergedEv.id2]));
    fprintf(1,'%d mobile devices(s) found...\n', sz(1));
    mergedEv = sortrows(mergedEv);
    ids1_map = table(unique([mergedEv.id1;mergedEv.id2]), (0:sz(1)-1)', 'VariableNames',{'id1', 'new_id'});
    ids2_map = table(unique([mergedEv.id1;mergedEv.id2]), (0:sz(1)-1)', 'VariableNames',{'id2', 'new_id'});
    joined = sortrows(outerjoin(mergedEv,ids1_map,'Key','id1'));
    fromMap = ~isnan(joined.time);
    mergedEv.id1 = joined.new_id(fromMap);
    joined = sortrows(outerjoin(mergedEv,ids2_map,'Key','id2'));
    fromMap = ~isnan(joined.time);
    mergedEv.id2 = joined.new_id(fromMap);
end
