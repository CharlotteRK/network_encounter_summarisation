function[] = find_encounters(file, ap_file, out_file)
    global raw encounters access_points;
    raw = readtable(file, "delimiter", ",");

    encounters = table('Size',[0 4],'VariableTypes',{'string','string','double', 'double'}, 'VariableNames',{'MAC1','MAC2','duration', 'frequency'});

    get_access_points();
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
    encounters.duration = encounters.duration ./ encounters.frequency;
    writetable(encounters, out_file,'Delimiter',',')
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
        line_i = encounters(strcmp(encounters.MAC1, encounter_i) & strcmp(encounters.MAC2, encounter_j),:);
        sz_i = size(line_i);
        line_j = encounters(strcmp(encounters.MAC1, encounter_j) & strcmp(encounters.MAC2, encounter_i),:);
        sz_j = size(line_j);
        if(sz_i(1) == 0 && sz_j(1) == 0)
            encounter = table(encounter_i, encounter_j, fin-strt, 1, 'VariableNames',{'MAC1','MAC2','duration', 'frequency'});
            encounters = [encounters;encounter];
        else
            if(sz_i(1) > 0)
                encounters(strcmp(encounters.MAC1, encounter_i) & strcmp(encounters.MAC2, encounter_j),:).duration = (line_i.duration + (fin-strt));
                encounters(strcmp(encounters.MAC1, encounter_i) & strcmp(encounters.MAC2, encounter_j),:).frequency = line_i.frequency + 1;
            elseif(sz_j(1) > 0)
                encounters(strcmp(encounters.MAC1, encounter_j) & strcmp(encounters.MAC2, encounter_i),:).duration = (line_j.duration + (fin-strt));
                encounters(strcmp(encounters.MAC1, encounter_j) & strcmp(encounters.MAC2, encounter_i),:).frequency = line_j.frequency + 1;
            end
        end
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
