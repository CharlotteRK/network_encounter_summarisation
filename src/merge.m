function[] = merge(folder, out_file)
    merged = table('Size',[0 5],'VariableTypes',{'double','string','string', 'string', 'string'}, 'VariableNames',{'time','type','id1', 'id2', 'subtype'});
    files = dir(fullfile(folder, '*.csv'));

    sz = size(files);
    for i = 1:sz(1)
        try
            raw = readtable(files[i], "delimiter", " ");
            merged = [merged ; raw];
        catch
            fprintf(2, "Error with merge input files. Incorrect delimiter or mismatched dimentions.");
            quit(1);
        end
    end

    merged = sortrows(merged);
    writetable(merged, out_file,'Delimiter',' ');
end
