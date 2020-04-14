function[] = find_events(file, ap_file, out_file)
    global raw encounters access_points;
    raw = readtable(file, "delimiter", ",", "FileType", "text");

    encounters = table('Size',[0 5],'VariableTypes',{'double','string','string', 'string', 'string'}, 'VariableNames',{'time','type','id1', 'id2', 'subtype'});

    get_access_points();
    sz_ap = size(access_points);
    fprintf(1,'%d access point(s) found...\n', sz_ap(1)); 
    src = ismember(raw.source,access_points.MAC);
    dest = ismember(raw.destination,access_points.MAC);
    raw = raw(src | dest,:);
    sz = size(raw);
    for i = 1:sz(1)
        for j = i+1:sz(1)
        	compare_associations(i, j);
            if (raw(j,:).start >= raw(i,:).fin)
            	break;
            end
        end
    end
    format long;
    writetable(access_points,ap_file,'Delimiter',',')
    writetable(encounters,out_file,'Delimiter',' ','WriteVariableNames',0)
end

function[] = get_access_points()
    global raw access_points;
    cond = raw.AP == 1;
    access_points = table(unique(raw(cond,:).destination), 'VariableNames', {'MAC'});
end

function[] = compare_associations(i, j)
    global raw encounters access_points;
    [overlap, strt, fin] = find_overlap(i, j);
    if(overlap <= 0)
       return;
    end
    if(strcmp(raw(i,:).source,raw(j,:).source))
        %if times match raw(i,1) is AP, encounter between raw(i,2) raw(j,2)
        ap = raw(i,:).source;
        encounter_i = raw(i,:).destination;
        encounter_j = raw(j,:).destination;
    elseif(strcmp(raw(i,:).source,raw(j,:).destination))
        %if times match raw(i,1) is AP, encounter between raw(i,2) raw(j,1)
        ap = raw(i,:).source;
        encounter_i = raw(i,:).destination;
        encounter_j = raw(j,:).source;
    elseif(strcmp(raw(i,:).destination,raw(j,:).source))
        %if times match raw(i,2) is AP, encounter between raw(i,1) raw(j,2)
        ap = raw(i,:).destination;
        encounter_i = raw(i,:).source;
        encounter_j = raw(j,:).destination;
    elseif(strcmp(raw(i,:).destination,raw(j,:).destination))
        %if times match raw(i,2) is AP, encounter between raw(i,1) raw(j,1)
        ap = raw(i,:).destination;
        encounter_i = raw(i,:).source;
        encounter_j = raw(j,:).source;
    else
        return;
    end
    access_point = table(ap, 'VariableNames', {'MAC'});
    enc_i = table(encounter_i, 'VariableNames', {'MAC'});
    enc_j = table(encounter_j, 'VariableNames', {'MAC'});
    if(1==ismember(access_point,access_points) && 0==ismember(enc_i,access_points) && 0==ismember(enc_j,access_points))
        encounter_strt = table(strt, "CONN", erasePunctuation(encounter_i), erasePunctuation(encounter_j), "up", 'VariableNames',{'time','type','id1', 'id2', 'subtype'});
        encounter_end = table(fin, "CONN", erasePunctuation(encounter_i), erasePunctuation(encounter_j), "down", 'VariableNames',{'time','type','id1', 'id2', 'subtype'});

        cond_enc = encounters.time < strt;
        encounters = [encounters(cond_enc,:); encounter_strt; encounters(~cond_enc,:)];
        cond_enc = encounters.time < fin;
        encounters = [encounters(cond_enc,:); encounter_end; encounters(~cond_enc,:)];
    end
end

function[overlap, greater_start, lower_end] = find_overlap(i, j)
    global raw;
    if(raw(i,:).start > raw(j,:).start)
        greater_start = raw(i,:).start;
    else
        greater_start = raw(j,:).start;
    end
    if(raw(i,:).fin < raw(j,:).fin)
        lower_end = raw(i,:).fin;
    else
        lower_end = raw(j,:).fin;
    end
    overlap = lower_end - greater_start;
end
